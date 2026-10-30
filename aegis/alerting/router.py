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

        if not allow_dispatch:
            # Suppressed by rate limiter / flap damper
            return alert

        # 4. Generate Zero-Trust signed triage link
        token = generate_triage_token(alert.alert_id, primary_contact.contact_id, ttl_seconds=900)
        triage_url = f"{self.base_console_url}/#triage?token={token}&aid={alert.alert_id}"

        # 5. Cascading Dispatch: Primary (ChatOps/Telegram/WhatsApp) -> Fallback (SMS) -> Out-Of-Band (Modem)
        dispatched_successfully = False

        # Channel 1: Primary ChatOps / Webhook / Telegram
        result_primary = await self.adapter_webhook.send(alert, primary_contact, triage_url)
        self.queue.record_dispatch_audit(alert.alert_id, result_primary)
        if result_primary.success:
            dispatched_successfully = True

        # Channel 2: Fallback Local Ghanaian SMS (if primary failed or not configured)
        if not dispatched_successfully:
            result_sms = await self.adapter_sms.send(alert, primary_contact, triage_url)
            self.queue.record_dispatch_audit(alert.alert_id, result_sms)
            if result_sms.success:
                dispatched_successfully = True

        # Channel 3: Out-Of-Band Cellular Serial Modem (if all IP networks failed)
        if not dispatched_successfully:
            result_modem = await self.adapter_modem.send(alert, primary_contact, triage_url)
            self.queue.record_dispatch_audit(alert.alert_id, result_modem)
            if result_modem.success:
                dispatched_successfully = True

        if dispatched_successfully:
            self.queue.mark_dispatched(alert.alert_id, "DELIVERED")
        else:
            self.queue.mark_retry(alert.alert_id, "All dispatch channels unconfigured or failed")

        return alert

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

                # Escalate via SMS directly to team lead / incident commander
                res = await self.adapter_sms.send(rebuilt_alert, contact, triage_url)
                self.queue.record_dispatch_audit(alert_id, res)

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
