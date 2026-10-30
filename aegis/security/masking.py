"""Mask secrets before they leave the process in a JSON response."""

from urllib.parse import urlparse
from typing import Dict


# JSON field -> environment variable. These values are never returned raw.
THREAT_INTEL_SECRETS = {
    "nvd_api_key": "NVD_API_KEY",
    "abuseipdb_api_key": "ABUSEIPDB_API_KEY",
    "otx_api_key": "OTX_API_KEY",
    "virustotal_api_key": "VIRUSTOTAL_API_KEY",
    "threatfox_auth_key": "THREATFOX_AUTH_KEY",
}

ALERTING_SECRETS = {
    "arkesel_api_key": "ARKESEL_API_KEY",
    "hubtel_client_id": "HUBTEL_CLIENT_ID",
    "hubtel_client_secret": "HUBTEL_CLIENT_SECRET",
    "telegram_bot_token": "TELEGRAM_BOT_TOKEN",
    "whatsapp_api_token": "WHATSAPP_API_TOKEN",
    "critical_alert_webhook_url": "CRITICAL_ALERT_WEBHOOK_URL",
    "canary_heartbeat_url": "CANARY_HEARTBEAT_URL",
    "slack_client_secret": "SLACK_CLIENT_SECRET",
    "microsoft_client_secret": "MICROSOFT_CLIENT_SECRET",
    "google_client_secret": "GOOGLE_CLIENT_SECRET",
}


def mask_secret(val: str) -> str:
    """Return a non-reversible preview. Empty stays empty. URLs keep only the host."""
    if val is None:
        return ""
    text = str(val).strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        parsed = urlparse(text)
        host = parsed.hostname or ""
        if host:
            return f"{parsed.scheme}://{host}/***"
    if len(text) <= 8:
        return "***"
    return f"{text[:4]}...{text[-4:]}"


def is_masked_echo(submitted: str, current: str) -> bool:
    """True when the client sent back the mask we just showed them."""
    if not submitted or not current:
        return False
    return str(submitted).strip() == mask_secret(current)


def mask_mapped_fields(section: Dict, field_map: Dict[str, str]) -> Dict:
    masked = dict(section)
    for field in field_map:
        if field in masked:
            masked[field] = mask_secret(masked.get(field) or "")
    return masked
