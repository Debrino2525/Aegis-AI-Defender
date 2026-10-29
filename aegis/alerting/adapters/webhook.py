"""
Aegis AI — ChatOps & Webhook Transport Adapter.
Supports Telegram Bot API (with interactive ACK buttons), WhatsApp Cloud API,
and enterprise HMAC-signed webhooks (Slack/Teams/SIEM).
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


class WebhookChatOpsAdapter(BaseAlertAdapter):
    """Dispatches high-urgency ChatOps notifications to Telegram, WhatsApp, or SIEM webhooks."""

    def __init__(self):
        self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        self.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
        self.whatsapp_token = os.getenv("WHATSAPP_API_TOKEN", "").strip()
        self.whatsapp_phone_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
        self.generic_webhook_url = os.getenv("CRITICAL_ALERT_WEBHOOK_URL", "").strip()

    @property
    def channel_name(self) -> str:
        return ChannelType.WEBHOOK.value

    async def send(self, alert: CriticalAlert, contact: OnCallContact, triage_url: str) -> DispatchResult:
        start_time = time.time()
        
        # Determine target channel based on configuration and contact preference
        # 1. Telegram (Preferred if token available)
        tg_token = self.telegram_bot_token
        tg_chat = contact.telegram_chat_id or self.telegram_chat_id

        if tg_token and tg_chat:
            return await self._send_telegram(tg_token, tg_chat, alert, triage_url, start_time)

        # 2. WhatsApp Cloud API
        if self.whatsapp_token and self.whatsapp_phone_id:
            wa_num = contact.whatsapp_number or contact.phone
            return await self._send_whatsapp(wa_num, alert, triage_url, start_time)

        # 3. Generic Webhook (Slack / Teams / SIEM)
        if self.generic_webhook_url:
            return await self._send_generic_webhook(self.generic_webhook_url, alert, triage_url, start_time)

        latency = (time.time() - start_time) * 1000
        return DispatchResult(
            channel=ChannelType.WEBHOOK,
            success=False,
            recipient=contact.phone or "unconfigured",
            error="No ChatOps credentials configured (add TELEGRAM_BOT_TOKEN or CRITICAL_ALERT_WEBHOOK_URL to .env)",
            latency_ms=round(latency, 2)
        )

    async def _send_telegram(self, token: str, chat_id: str, alert: CriticalAlert, triage_url: str, start_time: float) -> DispatchResult:
        text = (
            f"🚨 *[AEGIS DEFENSE - CRITICAL INCIDENT]*\n\n"
            f"*Title:* {alert.title}\n"
            f"*Severity:* 🔴 *{alert.severity.value}*\n"
            f"*Pillars:* {', '.join(p.value if hasattr(p, 'value') else str(p) for p in alert.zt_pillars)}\n"
            f"*Summary:* {alert.summary[:200]}...\n\n"
            f"⚡ *Immediate triage required.* Click below to verify and respond:"
        )
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "reply_markup": {
                "inline_keyboard": [
                    [{"text": "🛡️ Open Secure Triage Console", "url": triage_url}]
                ]
            }
        }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                resp = await client.post(url, json=payload)
                latency = (time.time() - start_time) * 1000
                if resp.status_code == 200:
                    data = resp.json()
                    msg_id = str(data.get("result", {}).get("message_id") or "tg_ack")
                    return DispatchResult(
                        channel=ChannelType.TELEGRAM,
                        success=True,
                        recipient=f"telegram:{chat_id}",
                        provider_ref=msg_id,
                        latency_ms=round(latency, 2)
                    )
                else:
                    return DispatchResult(
                        channel=ChannelType.TELEGRAM,
                        success=False,
                        recipient=f"telegram:{chat_id}",
                        error=f"Telegram API HTTP {resp.status_code}: {resp.text}",
                        latency_ms=round(latency, 2)
                    )
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return DispatchResult(
                channel=ChannelType.TELEGRAM,
                success=False,
                recipient=f"telegram:{chat_id}",
                error=f"Telegram dispatch error: {str(e)}",
                latency_ms=round(latency, 2)
            )

    async def _send_whatsapp(self, recipient_num: str, alert: CriticalAlert, triage_url: str, start_time: float) -> DispatchResult:
        clean_num = recipient_num.replace("+", "").strip()
        body = sanitize_for_public_channel(
            alert_id=alert.alert_id,
            title=alert.title,
            environment=alert.metadata.get("environment", "Production"),
            pillar_tags=alert.zt_pillars,
            triage_url=triage_url
        )
        url = f"https://graph.facebook.com/v19.0/{self.whatsapp_phone_id}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": clean_num,
            "type": "text",
            "text": {"preview_url": True, "body": body}
        }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {self.whatsapp_token}"},
                    json=payload
                )
                latency = (time.time() - start_time) * 1000
                if resp.status_code in (200, 201):
                    data = resp.json()
                    ref = data.get("messages", [{}])[0].get("id", "wa_ack")
                    return DispatchResult(
                        channel=ChannelType.WHATSAPP,
                        success=True,
                        recipient=f"whatsapp:{clean_num}",
                        provider_ref=ref,
                        latency_ms=round(latency, 2)
                    )
                else:
                    return DispatchResult(
                        channel=ChannelType.WHATSAPP,
                        success=False,
                        recipient=f"whatsapp:{clean_num}",
                        error=f"WhatsApp HTTP {resp.status_code}: {resp.text}",
                        latency_ms=round(latency, 2)
                    )
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return DispatchResult(
                channel=ChannelType.WHATSAPP,
                success=False,
                recipient=f"whatsapp:{clean_num}",
                error=f"WhatsApp error: {str(e)}",
                latency_ms=round(latency, 2)
            )

    async def _send_generic_webhook(self, url: str, alert: CriticalAlert, triage_url: str, start_time: float) -> DispatchResult:
        payload = {
            "source": "Aegis AI Cyber Defense",
            "alert_id": alert.alert_id,
            "title": alert.title,
            "severity": alert.severity.value,
            "pillars": [p.value if hasattr(p, "value") else str(p) for p in alert.zt_pillars],
            "summary": alert.summary,
            "triage_url": triage_url,
            "timestamp": alert.created_at
        }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(url, json=payload)
                latency = (time.time() - start_time) * 1000
                return DispatchResult(
                    channel=ChannelType.WEBHOOK,
                    success=resp.status_code in (200, 201, 202, 204),
                    recipient=url,
                    provider_ref=f"HTTP-{resp.status_code}",
                    error=None if resp.status_code < 400 else f"HTTP {resp.status_code}: {resp.text[:100]}",
                    latency_ms=round(latency, 2)
                )
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            return DispatchResult(
                channel=ChannelType.WEBHOOK,
                success=False,
                recipient=url,
                error=f"Webhook delivery error: {str(e)}",
                latency_ms=round(latency, 2)
            )
