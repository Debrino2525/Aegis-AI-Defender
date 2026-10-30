"""
Aegis AI — Central Critical Alert Router & Orchestrator.
Coordinates alert classification, deduplication, persistent SQLite queueing,
multi-channel primary/fallback dispatching, and escalation timers.
"""

import os
import asyncio
from typing import Dict, Any, Optional, List
from aegis.alerting.models import (
    CriticalAlert, OnCallContact, DispatchResult, ChannelType, SeverityLevel
)
from aegis.alerting.queue import AlertQueue
from aegis.alerting.classifier import AlertClassifier
from aegis.alerting.dedup import FlapDamper
from aegis.alerting.cap import DispatchCap
from aegis.alerting.integrations import PlatformConnections, deliver, message_text
from aegis.alerting.escalation import EscalationManager
from aegis.alerting.security import generate_triage_token
from aegis.alerting.adapters.sms_local import LocalSMSAdapter
from aegis.alerting.adapters.webhook import WebhookChatOpsAdapter
from aegis.alerting.adapters.modem_oob import ModemOOBAdapter
from aegis.alerting.heartbeat import CanaryHeartbeat


class AlertRouter:
    """Master orchestrator for all critical alert routing, escalation, and dispatching."""

    def __init__(self, queue: Optional[AlertQueue] = None):
        self.queue = queue or AlertQueue()
        self.classifier = AlertClassifier()
        self.damper = FlapDamper(flap_window_seconds=900, max_alerts_per_window=3)
        self.cap = DispatchCap(self.queue)
        self.platforms = PlatformConnections(self.queue)
        self.escalation = EscalationManager(queue=self.queue)
        
        # Channel Adapters
        self.adapter_webhook = WebhookChatOpsAdapter()
        self.adapter_sms = LocalSMSAdapter()
        self.adapter_modem = ModemOOBAdapter()
        
        # Canary Heartbeat
        self.heartbeat = CanaryHeartbeat(ping_interval_seconds=60)
        
        # Base console URL for triage links
        self.base_console_url = os.getenv("AEGIS_CONSOLE_URL", "http://localhost:8000").rstrip("/")
        
        # Background escalation worker
        self._escalation_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Starts the router's background escalation checker and heartbeat."""
        if self._running:
            return
        self._running = True
        self._escalation_task = asyncio.create_task(self._escalation_loop())

    def stop(self):
        self._running = False
        self.heartbeat.stop()
        if self._escalation_task:
            self._escalation_task.cancel()

    async def _escalation_loop(self):
        """Periodic background task that checks for unacknowledged alerts needing escalation."""
        while self._running:
            try:
                await self.process_escalations()
            except asyncio.CancelledError:
                break
            except Exception as e:
                pass
            await asyncio.sleep(20)

    async def route_behavioral_alert(self, alert_dict: Dict[str, Any]) -> Optional[CriticalAlert]:
        """Processes a raw behavioral alert through the complete critical routing pipeline."""
        critical_alert = self.classifier.classify_behavioral_alert(alert_dict)
        if not critical_alert:
            return None  # Normal low/medium alert; handled by standard dashboard

        return await self._dispatch_critical_alert(critical_alert)

    async def route_scan_finding(self, target: str, finding_dict: Dict[str, Any]) -> Optional[CriticalAlert]:
        """Processes a vulnerability scan finding through the critical routing pipeline."""
        critical_alert = self.classifier.classify_scan_finding(target, finding_dict)
        if not critical_alert:
            return None

        return await self._dispatch_critical_alert(critical_alert)

    async def _dispatch_critical_alert(self, alert: CriticalAlert) -> CriticalAlert:
        """Enforces flap damping, resolves ownership, enqueues, and executes cascading dispatch."""
        # 1. Deduplication & Flap Control
        allow_dispatch, reason, count = self.damper.should_dispatch(alert.fingerprint)
        alert.occurrence_count = count
        
        # 2. Resolve on-call responder for this target
        primary_contact, lead_contact, env_label, timeout_mins = self.escalation.resolve_contacts_for_target(alert.source_ip)
        alert.metadata["environment"] = env_label
        alert.metadata["primary_contact_id"] = primary_contact.contact_id if primary_contact else None

        # 3. Enqueue in persistent SQLite queue
        is_new = self.queue.enqueue_alert(alert)

        if primary_contact is None:
            if allow_dispatch:
                self.queue.mark_retry(alert.alert_id, "No on-call contact configured")
            return alert

        if self.queue.is_paged(alert.alert_id) or not allow_dispatch:
            self.cap.note_held(alert.alert_id)
            return alert

        slot = self.cap.reserve()
        if slot == "hold":
            self.cap.note_held(alert.alert_id)
            return alert
        if slot == "summary":
            self.cap.note_held(alert.alert_id)
            sent = await self._send_cap_summary(alert, primary_contact)
            if not sent:
                self.cap.release_summary()
            return alert

        # 4. Generate Zero-Trust signed triage link
        token = generate_triage_token(alert.alert_id, primary_contact.contact_id, ttl_seconds=900)
        triage_url = f"{self.base_console_url}/#triage?token={token}&aid={alert.alert_id}"

        dispatched_successfully = await self._send_outside(alert, primary_contact, triage_url)

        if dispatched_successfully:
            self.queue.mark_paged(alert.alert_id)
            self.queue.mark_dispatched(alert.alert_id, "DELIVERED")
        else:
            self.cap.release_page()
            self.queue.mark_retry(alert.alert_id, "All dispatch channels unconfigured or failed")

        return alert

    async def _deliver_platform(self, contact: OnCallContact, title: str, summary: str, link: str):
        """Page the connected Slack, Teams, or email account. None means none is connected."""
        connection = self.platforms.destination_for(contact.contact_id)
        if connection is None:
            return None
        return await deliver(connection, message_text(title, summary, link))

    async def _send_outside(self, alert: CriticalAlert, contact: OnCallContact, triage_url: str) -> bool:
        """Page the connected Slack, Teams, or email account."""
        platform_result = await self._deliver_platform(contact, alert.title, alert.summary, triage_url)
        if platform_result is None:
            return False
        self.queue.record_dispatch_audit(alert.alert_id, platform_result)
        return bool(platform_result.success)

    async def _send_cap_summary(self, alert: CriticalAlert, contact: OnCallContact) -> bool:
        """One message for the hour after the cap is used. Not a new incident."""
        picture = self.cap.snapshot()
        summary = CriticalAlert(
            alert_id=f"CAP-{picture['hour']}",
            fingerprint="dispatch-cap-summary",
            title="Outside channel cap reached",
            severity=SeverityLevel.CRITICAL,
            summary=(
                f"Held {picture['held_this_hour']} alerts this hour after "
                f"{picture['hourly_cap']} outside messages. "
                f"Latest: {alert.title} from {alert.source_ip}. "
                "Review them in the console."
            ),
            source_ip=alert.source_ip,
        )
        platform_result = await self._deliver_platform(
            contact, summary.title, summary.summary, self.base_console_url
        )
        if platform_result is None:
            return False
        return bool(platform_result.success)

    async def process_escalations(self):
        """Scans unacknowledged alerts and advances escalation levels if timers have elapsed."""
        unacknowledged = self.queue.get_unacknowledged_alerts()
        for alert_dict in unacknowledged:
            needs_esc, new_level, contact = self.escalation.check_escalation_needed(alert_dict)
            if needs_esc and contact:
                alert_id = alert_dict["alert_id"]
                # Advance level in DB
                with self.queue._get_conn() as conn:
                    conn.execute("UPDATE critical_alerts SET escalation_level = ? WHERE alert_id = ?", (new_level, alert_id))

                # Reconstruct minimal alert model
                rebuilt_alert = CriticalAlert(
                    alert_id=alert_id,
                    fingerprint=alert_dict["fingerprint"],
                    title=f"[ESCALATION LEVEL {new_level}] {alert_dict['title']}",
                    severity=SeverityLevel.CRITICAL,
                    summary=f"UNACKNOWLEDGED INCIDENT ESCALATED TO LEVEL {new_level}. {alert_dict['summary']}",
                    source_ip=alert_dict["source_ip"],
                    created_at=alert_dict["created_at"],
                    escalation_level=new_level,
                    metadata=alert_dict.get("metadata", {})
                )

                token = generate_triage_token(alert_id, contact.contact_id, ttl_seconds=900)
                triage_url = f"{self.base_console_url}/#triage?token={token}&aid={alert_id}"

                slot = self.cap.reserve()
                if slot != "page":
                    self.cap.note_held(alert_id)
                    if slot == "summary":
                        sent = await self._send_cap_summary(rebuilt_alert, contact)
                        if not sent:
                            self.cap.release_summary()
                    continue

                platform_result = await self._deliver_platform(
                    contact, rebuilt_alert.title, rebuilt_alert.summary, triage_url
                )
                if platform_result is None:
                    self.cap.release_page()
                    continue
                self.queue.record_dispatch_audit(alert_id, platform_result)
                if not platform_result.success:
                    self.cap.release_page()

    async def page_closed_loop(self, incident: Dict[str, Any], action: Dict[str, Any]) -> Dict[str, Any]:
        """Page Slack/Teams/email after an operator confirms isolate on a closed loop.

        Uses the existing hourly cap. Dashboard still shows routing status only.
        """
        loop = incident.get("loop") if isinstance(incident.get("loop"), dict) else {}
        picture = self.cap.snapshot()
        base = {
            "hourly_cap": picture["hourly_cap"],
            "sent_this_hour": picture["sent_this_hour"],
            "held_this_hour": picture["held_this_hour"],
            "provider": None,
        }
        if not loop.get("closed"):
            return {**base, "status": "skipped", "reason": "Incident is not a closed Prevent → Detect loop."}
        if str(action.get("action") or "") != "quarantine_host":
            return {**base, "status": "skipped", "reason": "Paging on confirm applies to isolate."}
        if str(action.get("status") or "") == "observed":
            return {**base, "status": "skipped", "reason": "Observe mode does not page."}
        if str(action.get("confirmed_by") or action.get("actor") or "") == "auto":
            return {**base, "status": "skipped", "reason": "Auto execution does not page; operator confirm does."}

        connection = self.platforms.first_destination()
        if connection is None:
            return {
                **base,
                "status": "no_destination",
                "reason": "No Slack, Teams, or email account is connected.",
            }

        finding_ids = [
            str(row.get("finding_id") or row.get("id"))
            for row in (loop.get("prevent") or {}).get("findings") or []
            if row.get("finding_id") or row.get("id")
        ]
        pattern_ids = list((loop.get("detect") or {}).get("pattern_ids") or [])
        host = (loop.get("host") or {}).get("hostname") or (incident.get("source_ips") or ["host"])[0]
        incident_id = str(incident.get("id") or "")
        action_id = str(action.get("action_id") or "")
        alert_id = f"LOOP-{(action_id or incident_id)[-12:]}"
        fingerprint = f"loop-isolate:{incident_id}:{action_id}"
        title = f"Isolate confirmed · {incident_id}"
        summary = (
            f"Operator confirmed isolate ({action.get('rule_id')}) on {host}. "
            f"Prevent findings: {', '.join(finding_ids) or 'none'}. "
            f"Detect: {', '.join(pattern_ids) or 'none'}. "
            f"Status {action.get('status')}. "
            f"Audit {(action.get('audit') or {}).get('signature', '')[:16]}."
        )
        page_alert = CriticalAlert(
            alert_id=alert_id,
            fingerprint=fingerprint,
            title=title,
            severity=SeverityLevel.CRITICAL,
            summary=summary,
            source_ip=str((incident.get("source_ips") or ["unknown"])[0]),
            metadata={
                "incident_id": incident_id,
                "action_id": action_id,
                "finding_ids": finding_ids,
                "pattern_ids": pattern_ids,
                "loop": True,
            },
        )
        self.queue.enqueue_alert(page_alert)
        if self.queue.is_paged(alert_id):
            held = self.cap.note_held(alert_id)
            picture = self.cap.snapshot()
            return {
                **base,
                "status": "held",
                "reason": "Already paged for this isolate.",
                "alert_id": alert_id,
                "hourly_cap": picture["hourly_cap"],
                "sent_this_hour": picture["sent_this_hour"],
                "held_this_hour": picture["held_this_hour"],
                "held_count": held,
                "provider": connection.get("provider"),
            }

        slot = self.cap.reserve()
        if slot == "hold":
            self.cap.note_held(alert_id)
            picture = self.cap.snapshot()
            return {
                **base,
                "status": "hold",
                "reason": "Hourly outside-message cap reached. Review this isolate in the console.",
                "alert_id": alert_id,
                "hourly_cap": picture["hourly_cap"],
                "sent_this_hour": picture["sent_this_hour"],
                "held_this_hour": picture["held_this_hour"],
                "provider": connection.get("provider"),
            }

        link = f"{self.base_console_url}/incidents?id={incident_id}"
        if slot == "summary":
            self.cap.note_held(alert_id)
            sent = await self._send_cap_summary(page_alert, OnCallContact(
                contact_id="loop",
                name="Loop",
                phone="+00000000000",
            ))
            picture = self.cap.snapshot()
            if not sent:
                self.cap.release_summary()
                return {
                    **base,
                    "status": "failed",
                    "reason": "Cap summary could not be delivered.",
                    "alert_id": alert_id,
                    "provider": connection.get("provider"),
                    "hourly_cap": picture["hourly_cap"],
                    "sent_this_hour": picture["sent_this_hour"],
                }
            return {
                **base,
                "status": "summary",
                "reason": "Hourly cap reached; one summary was sent.",
                "alert_id": alert_id,
                "provider": connection.get("provider"),
                "hourly_cap": picture["hourly_cap"],
                "sent_this_hour": picture["sent_this_hour"],
                "held_this_hour": picture["held_this_hour"],
            }

        result = await deliver(connection, message_text(title, summary, link))
        if result is None or not result.success:
            self.cap.release_page()
            return {
                **base,
                "status": "failed",
                "reason": (result.error if result else "delivery failed") or "delivery failed",
                "alert_id": alert_id,
                "provider": connection.get("provider"),
            }
        self.queue.record_dispatch_audit(alert_id, result)
        self.queue.mark_paged(alert_id)
        self.queue.mark_dispatched(alert_id, "DELIVERED")
        picture = self.cap.snapshot()
        return {
            "status": "page",
            "provider": connection.get("provider"),
            "alert_id": alert_id,
            "hourly_cap": picture["hourly_cap"],
            "sent_this_hour": picture["sent_this_hour"],
            "held_this_hour": picture["held_this_hour"],
            "destination_label": connection.get("account_label") or connection.get("provider"),
        }

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledges an alert, halting all active escalation timers."""
        return self.queue.acknowledge_alert(alert_id, acknowledged_by)

    def get_status(self) -> Dict[str, Any]:
        """Returns live statistics of the alert routing engine."""
        recent = self.queue.list_recent_alerts(limit=50)
        unacked = [a for a in recent if not a.get("acknowledged")]
        return {
            "running": self._running,
            "total_recent_critical_alerts": len(recent),
            "unacknowledged_critical_count": len(unacked),
            "contacts_count": len(self.escalation.contacts),
            "dispatch_cap": self.cap.snapshot(),
            "platforms": self.platforms.public(),
        }


# Singleton instance
alert_router = AlertRouter()
