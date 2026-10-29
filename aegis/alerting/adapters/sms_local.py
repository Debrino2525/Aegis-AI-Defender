"""
Aegis AI — Local Ghanaian SMS & Voice Telephony Adapter.
Integrates with Arkesel and Hubtel SMS/Voice APIs for high-reliability West African delivery.
"""

import os
import time
import httpx
from typing import Optional
from dotenv import load_dotenv
from aegis.alerting.models import CriticalAlert, OnCallContact, DispatchResult, ChannelType
from aegis.alerting.adapters.base import BaseAlertAdapter
from aegis.alerting.security import sanitize_for_public_channel

load_dotenv()


class LocalSMSAdapter(BaseAlertAdapter):
    """
    Local aggregator adapter for Ghana telecommunications networks (MTN, Telecel, AT).
    Primary backend: Arkesel SMS API v2
    Secondary backend: Hubtel SMS API
    """

    def __init__(self):
        self.arkesel_api_key = os.getenv("ARKESEL_API_KEY", "").strip()
        self.arkesel_sender = os.getenv("ARKESEL_SENDER_ID", "AegisAI").strip()[:11]
        self.hubtel_client_id = os.getenv("HUBTEL_CLIENT_ID", "").strip()
        self.hubtel_client_secret = os.getenv("HUBTEL_CLIENT_SECRET", "").strip()
        self.hubtel_sender = os.getenv("HUBTEL_SENDER_ID", "AegisAI").strip()[:11]

    @property
    def channel_name(self) -> str:
        return ChannelType.SMS_LOCAL.value

    async def send(self, alert: CriticalAlert, contact: OnCallContact, triage_url: str) -> DispatchResult:
        start_time = time.time()
        recipient_phone = contact.phone.strip()
        
        # Build sanitized public SMS message (no private IPs/CVE details)
        message_body = sanitize_for_public_channel(
            alert_id=alert.alert_id,
            title=alert.title,
            environment=alert.metadata.get("environment", "Production"),
            pillar_tags=alert.zt_pillars,
            triage_url=triage_url
        )

        # Check if keys are configured
        if not self.arkesel_api_key and not self.hubtel_client_id:
            latency = (time.time() - start_time) * 1000
            return DispatchResult(
                channel=ChannelType.SMS_LOCAL,
                success=False,
                recipient=recipient_phone,
                error="Neither ARKESEL_API_KEY nor HUBTEL_CLIENT_ID configured in .env (add key to activate SMS)",
                latency_ms=round(latency, 2)
            )

        # Try Arkesel first
        if self.arkesel_api_key:
            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.post(
                        "https://sms.arkesel.com/api/v2/sms/send",
                        headers={"api-key": self.arkesel_api_key},
                        json={
                            "sender": self.arkesel_sender,
                            "message": message_body,
                            "recipients": [recipient_phone]
                        }
                    )
                    latency = (time.time() - start_time) * 1000
                    data = resp.json() if resp.status_code == 200 else {}
                    if resp.status_code == 200 and data.get("status") in ("success", "100"):
                        return DispatchResult(
                            channel=ChannelType.SMS_LOCAL,
                            success=True,
                            recipient=recipient_phone,
                            provider_ref=str(data.get("data", {}).get("message_id") or "arkesel_ack"),
                            latency_ms=round(latency, 2)
                        )
                    else:
                        err_msg = data.get("message") or f"HTTP {resp.status_code}: {resp.text}"
            except Exception as e:
                err_msg = f"Arkesel connection error: {str(e)}"

        # Failover to Hubtel if available
        if self.hubtel_client_id and self.hubtel_client_secret:
            try:
                auth = (self.hubtel_client_id, self.hubtel_client_secret)
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(
                        "https://sms.hubtel.com/v1/messages/send",
                        auth=auth,
                        params={
                            "From": self.hubtel_sender,
                            "To": recipient_phone,
                            "Content": message_body
                        }
                    )
                    latency = (time.time() - start_time) * 1000
                    if resp.status_code in (200, 201):
                        data = resp.json()
                        return DispatchResult(
                            channel=ChannelType.SMS_LOCAL,
                            success=True,
                            recipient=recipient_phone,
                            provider_ref=str(data.get("MessageId") or "hubtel_ack"),
                            latency_ms=round(latency, 2)
                        )
                    else:
                        err_msg = f"Hubtel HTTP {resp.status_code}: {resp.text}"
            except Exception as e:
                err_msg = f"Hubtel connection error: {str(e)}"

        latency = (time.time() - start_time) * 1000
        return DispatchResult(
            channel=ChannelType.SMS_LOCAL,
            success=False,
            recipient=recipient_phone,
            error=err_msg,
            latency_ms=round(latency, 2)
        )
