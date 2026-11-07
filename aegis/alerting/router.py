"""
Aegis AI — Central Critical Alert Router & Orchestrator.
Coordinates alert classification, deduplication, persistent SQLite queueing,
multi-channel primary/fallback dispatching, and escalation timers.
"""

import os
import asyncio
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from aegis.alerting.models import (
    CriticalAlert, OnCallContact, DispatchResult, ChannelType, SeverityLevel
)
from aegis.alerting.queue import AlertQueue
from aegis.alerting.classifier import AlertClassifier
from aegis.alerting.dedup import FlapDamper
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
        # alert_id -> last failed escalation attempt (unix seconds). Stops a
        # down channel from being retried on every 20s loop tick.
        self._escalation_attempts: Dict[str, float] = {}

    async def start(self):
        """Starts the router's background escalation checker and heartbeat."""
        if self._running:
            return
        self._running = True
        await self.heartbeat.start()
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
                await self.process_due_retries()
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
        alert.metadata["primary_contact_id"] = primary_contact.contact_id

        # 3. Enqueue in persistent SQLite queue
        is_new = self.queue.enqueue_alert(alert)

        if not allow_dispatch:
            # Suppressed by rate limiter / flap damper
            return alert

        # 4. Generate Zero-Trust signed triage link
        token = generate_triage_token(alert.alert_id, primary_contact.contact_id, ttl_seconds=900)
        triage_url = f"{self.base_console_url}/#triage?token={token}&aid={alert.alert_id}"

        # 5. Cascading Dispatch: Primary (ChatOps/Telegram/WhatsApp) -> Fallback (SMS) -> Out-Of-Band (Modem)
        if await self._cascade_dispatch(alert, primary_contact, triage_url):
            self.queue.mark_dispatched(alert.alert_id, "DELIVERED")
        else:
            self.queue.mark_retry(alert.alert_id, "All dispatch channels unconfigured or failed")

        return alert

    async def _cascade_dispatch(self, alert: CriticalAlert, contact: OnCallContact, triage_url: str) -> bool:
        """Sends through ChatOps, then SMS, then the modem. Stops at the first success.

        An adapter that raises is recorded as a failed attempt so the next
        channel still runs. One broken gateway must not drop the page.
        """
        for adapter in (self.adapter_webhook, self.adapter_sms, self.adapter_modem):
            try:
                result = await adapter.send(alert, contact, triage_url)
            except Exception as exc:
                result = DispatchResult(
                    channel=ChannelType.CONSOLE,
                    success=False,
                    recipient=contact.contact_id or contact.phone or "unknown",
                    error=f"{adapter.__class__.__name__} raised {type(exc).__name__}: {exc}",
                )
            self.queue.record_dispatch_audit(alert.alert_id, result)
            if result.success:
                return True
        return False

    def _rebuild_alert(self, alert_dict: Dict[str, Any], title: str, summary: str, escalation_level: int) -> CriticalAlert:
        raw_severity = alert_dict.get("severity", SeverityLevel.CRITICAL)
        try:
            severity = raw_severity if isinstance(raw_severity, SeverityLevel) else SeverityLevel(str(raw_severity))
        except ValueError:
            severity = SeverityLevel.CRITICAL
        return CriticalAlert(
            alert_id=alert_dict["alert_id"],
            fingerprint=alert_dict["fingerprint"],
            title=title,
            severity=severity,
            summary=summary,
            source_ip=alert_dict.get("source_ip") or "",
            dest_ip=alert_dict.get("dest_ip"),
            dest_port=alert_dict.get("dest_port"),
            process=alert_dict.get("process"),
            tactic=alert_dict.get("tactic"),
            technique=alert_dict.get("technique"),
            cve_id=alert_dict.get("cve_id"),
            created_at=alert_dict.get("created_at") or datetime.now(timezone.utc).isoformat(),
            escalation_level=escalation_level,
            metadata=alert_dict.get("metadata") or {},
        )

    async def process_due_retries(self):
        """Re-sends dispatches that failed and whose backoff has elapsed.

        Fresh PENDING alerts are left to the inline dispatcher. This only
        picks rows already marked DISPATCHING, so a page is not sent twice
        while the first attempt is still in flight.
        """
        for alert_dict in self.queue.get_due_retries(limit=10):
            alert_id = alert_dict["alert_id"]
            if not self.queue.lease_retry(alert_id):
                continue
            primary, _, _, _ = self.escalation.resolve_contacts_for_target(alert_dict.get("source_ip") or "")
            rebuilt = self._rebuild_alert(
                alert_dict,
                title=alert_dict["title"],
                summary=alert_dict["summary"],
                escalation_level=int(alert_dict.get("escalation_level") or 0),
            )
            token = generate_triage_token(alert_id, primary.contact_id, ttl_seconds=900)
            triage_url = f"{self.base_console_url}/#triage?token={token}&aid={alert_id}"
            if await self._cascade_dispatch(rebuilt, primary, triage_url):
                self.queue.mark_dispatched(alert_id, "DELIVERED")
            else:
                self.queue.mark_retry(alert_id, "All dispatch channels unconfigured or failed")

    async def process_escalations(self):
        """Pages the escalation contact on a configured channel once the timer elapses.

        The level is stored only after a channel accepts the page. Recording
        the level first made a failed SMS look escalated and blocked a retry
        of that same level. Teams that page through Telegram, WhatsApp, or a
        webhook never reached the lead, because escalation tried SMS only.
        """
        now = time.time()
        unacknowledged = self.queue.get_unacknowledged_alerts()
        for alert_dict in unacknowledged:
            needs_esc, new_level, contact = self.escalation.check_escalation_needed(alert_dict)
            if not (needs_esc and contact):
                continue
            alert_id = alert_dict["alert_id"]
            last_attempt = self._escalation_attempts.get(alert_id, 0.0)
            if now - last_attempt < 60:
                continue

            rebuilt_alert = self._rebuild_alert(
                alert_dict,
                title=f"[ESCALATION LEVEL {new_level}] {alert_dict['title']}",
                summary=f"UNACKNOWLEDGED INCIDENT ESCALATED TO LEVEL {new_level}. {alert_dict['summary']}",
                escalation_level=new_level,
            )
            token = generate_triage_token(alert_id, contact.contact_id, ttl_seconds=900)
            triage_url = f"{self.base_console_url}/#triage?token={token}&aid={alert_id}"

            self._escalation_attempts[alert_id] = now
            if not await self._cascade_dispatch(rebuilt_alert, contact, triage_url):
                continue

            with self.queue._get_conn() as conn:
                conn.execute(
                    "UPDATE critical_alerts SET escalation_level = ? WHERE alert_id = ? AND acknowledged = 0",
                    (new_level, alert_id),
                )
            self._escalation_attempts.pop(alert_id, None)

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
            "channels": {
                "sms_local_arkesel": bool(self.adapter_sms.arkesel_api_key),
                "sms_local_hubtel": bool(self.adapter_sms.hubtel_client_id),
                "telegram": bool(self.adapter_webhook.telegram_bot_token),
                "whatsapp": bool(self.adapter_webhook.whatsapp_token),
                "generic_webhook": bool(self.adapter_webhook.generic_webhook_url),
                "modem_oob_configured": bool(self.adapter_modem.port)
            },
            "canary_heartbeat": self.heartbeat.get_status()
        }


# Singleton instance
alert_router = AlertRouter()
