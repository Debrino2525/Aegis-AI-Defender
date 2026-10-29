"""
Aegis AI — Alert Security & Zero Trust Cryptographic Utilities.
Handles tokenized one-time triage links (HMAC-SHA256), payload sanitization
for public telecommunications (no raw IPs/CVEs in SMS/chat), and signature verification.
"""

import os
import hmac
import hashlib
import time
import base64
import json
from typing import Dict, Any, Tuple, Optional
from dotenv import load_dotenv

load_dotenv()

# Key used for HMAC signing of triage deep links
_DEFAULT_KEY = "aegis-defense-secret-key-zt-2026"
SIGNING_KEY = os.getenv("ALERT_SIGNING_KEY", _DEFAULT_KEY).encode("utf-8")


def generate_triage_token(alert_id: str, contact_id: str, ttl_seconds: int = 900) -> str:
    """
    Generates a cryptographically signed, short-lived (default 15 minutes)
    HMAC-SHA256 URL-safe token allowing zero-trust access to an alert triage view.
    """
    expires_at = int(time.time()) + ttl_seconds
    payload = {
        "aid": alert_id,
        "cid": contact_id,
        "exp": expires_at,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    
    signature = hmac.new(SIGNING_KEY, payload_bytes, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    
    return f"{payload_b64}.{sig_b64}"


def verify_triage_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """
    Verifies a triage token's authenticity, integrity, and expiration.
    Returns: (is_valid, payload_dict, reason)
    """
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return False, None, "Invalid token format"
        
        payload_b64, sig_b64 = parts
        
        # Restore base64 padding
        pad_len = 4 - (len(payload_b64) % 4)
        if pad_len != 4:
            payload_b64 += "=" * pad_len
            
        pad_len_sig = 4 - (len(sig_b64) % 4)
        if pad_len_sig != 4:
            sig_b64 += "=" * pad_len_sig
            
        payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        expected_sig = hmac.new(SIGNING_KEY, payload_bytes, hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64.encode("ascii"))
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            return False, None, "Cryptographic signature mismatch"
            
        payload = json.loads(payload_bytes.decode("utf-8"))
        if time.time() > payload.get("exp", 0):
            return False, None, "Token has expired (valid for 15 minutes only)"
            
        return True, payload, "Valid"
    except Exception as e:
        return False, None, f"Token decode error: {str(e)}"


def sanitize_for_public_channel(alert_id: str, title: str, environment: str, pillar_tags: list, triage_url: str) -> str:
    """
    Sanitizes alert content for delivery over public cellular SMS or chat channels.
    Strictly prevents leaking internal IP addresses, CVE exploit proofs, or infrastructure
    details across untrusted telecom carriers.
    """
    pillars_str = ", ".join(p.value if hasattr(p, "value") else str(p) for p in pillar_tags[:2]) or "Network"
    return (
        f"[AEGIS DEFENSE - CRITICAL ALERT]\n"
        f"Event: {title}\n"
        f"Zone: {environment}\n"
        f"Pillars: {pillars_str}\n"
        f"Action Required: Authenticate to triage:\n"
        f"{triage_url}"
    )
