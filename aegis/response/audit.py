"""HMAC-SHA256 audit records for every response action."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Dict, Mapping

from aegis.alerting.security import bootstrap_signing_key, signing_key_source, signing_key_text


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def sign_audit(payload: Mapping[str, Any]) -> Dict[str, Any]:
    bootstrap_signing_key()
    canonical = _canonical(payload)
    signature = hmac.new(
        signing_key_text().encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "alg": "HMAC-SHA256",
        "canonical": canonical,
        "signature": signature,
        "key_source": signing_key_source(),
        "payload": dict(payload),
    }


def verify_audit(audit: Mapping[str, Any]) -> bool:
    if not isinstance(audit, Mapping):
        return False
    payload = audit.get("payload")
    signature = audit.get("signature")
    if not isinstance(payload, Mapping) or not signature:
        return False
    expected = sign_audit(payload)
    return hmac.compare_digest(expected["signature"], str(signature))
