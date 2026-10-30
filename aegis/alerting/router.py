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

    def _channel_ready(self, contact: OnCallContact) -> bool:
        webhook = self.adapter_webhook
        telegram_chat = (contact.telegram_chat_id or webhook.telegram_chat_id or "").strip()
        if webhook.telegram_bot_token and telegram_chat:
            return True
        if webhook.whatsapp_token and webhook.whatsapp_phone_id:
            return True
        if webhook.generic_webhook_url:
            return True
        if self.adapter_sms.arkesel_api_key or self.adapter_sms.hubtel_client_id:
            return True
        return bool(self.adapter_modem.port)

    async def _send_outside(self, alert: CriticalAlert, contact: OnCallContact, triage_url: str) -> bool:
        """Page one channel. Chat, then SMS, then the modem. Stops at the first success."""
        result_primary = await self.adapter_webhook.send(alert, contact, triage_url)
        self.queue.record_dispatch_audit(alert.alert_id, result_primary)
        if result_primary.success:
            return True
        result_sms = await self.adapter_sms.send(alert, contact, triage_url)
        self.queue.record_dispatch_audit(alert.alert_id, result_sms)
        if result_sms.success:
            return True
        result_modem = await self.adapter_modem.send(alert, contact, triage_url)
        self.queue.record_dispatch_audit(alert.alert_id, result_modem)
        return bool(result_modem.success)

    async def _send_cap_summary(self, alert: CriticalAlert, contact: OnCallContact) -> bool:
        """One message for the hour after the cap is used. Not a new incident."""
        if not self._channel_ready(contact):
            return False
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
        result_primary = await self.adapter_webhook.send(summary, contact, self.base_console_url)
        if result_primary.success:
            return True
        result_sms = await self.adapter_sms.send(summary, contact, self.base_console_url)
        if result_sms.success:
            return True
        result_modem = await self.adapter_modem.send(summary, contact, self.base_console_url)
        return bool(result_modem.success)

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

                # Escalate via SMS directly to team lead / incident commander
                res = await self.adapter_sms.send(rebuilt_alert, contact, triage_url)
                self.queue.record_dispatch_audit(alert_id, res)
                if not res.success:
                    self.cap.release_page()

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
            "canary_heartbeat": self.heartbeat.get_status(),
            "dispatch_cap": self.cap.snapshot(),
        }


# Singleton instance
alert_router = AlertRouter()
