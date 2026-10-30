"""
Aegis AI — Alert Security & Zero Trust Cryptographic Utilities.
Handles tokenized one-time triage links (HMAC-SHA256), payload sanitization
for public telecommunications (no raw IPs/CVEs in SMS/chat), and signature verification.
"""

import os
import sys
import hmac
import hashlib
import time
import base64
import json
import secrets
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from dotenv import load_dotenv

from aegis.runtime import aegis_data_dir

load_dotenv()

# Published in older .env.example copies. Never use it to sign triage links.
PUBLIC_DEFAULT_SIGNING_KEY = "aegis-defense-secret-key-zt-2026"
SIGNING_KEY = b""
SIGNING_KEY_SOURCE = ""
SIGNING_KEY_WARNING = ""
_bootstrapped = False


def is_public_default_signing_key(value: str) -> bool:
    return (value or "").strip() == PUBLIC_DEFAULT_SIGNING_KEY


def is_dev_mode() -> bool:
    if os.getenv("AEGIS_DEV", "").strip().lower() in ("1", "true", "yes"):
        return True
    return os.getenv("AEGIS_ENV", "").strip().lower() in ("dev", "development", "test")


def _insecure_default_allowed(dev: bool, allow_insecure: Optional[bool]) -> bool:
    if allow_insecure is not None:
        return bool(dev and allow_insecure)
    if not dev:
        return False
    return os.getenv("AEGIS_ALLOW_INSECURE_SIGNING_KEY", "").strip().lower() in ("1", "true", "yes")


def resolve_signing_key(
    env_value: Optional[str] = None,
    data_dir: Optional[Path] = None,
    dev: Optional[bool] = None,
    allow_insecure: Optional[bool] = None,
) -> Tuple[bytes, str, Optional[str]]:
    """
    Pick the HMAC key. A missing or public-default value is rejected.
    Outside dev (and in dev unless AEGIS_ALLOW_INSECURE_SIGNING_KEY=1),
    a key is generated and stored under the data dir, outside the repo.
    Returns (key_bytes, source, warning). source is env, persisted, generated, or insecure-default.
    """
    if env_value is None:
        raw = os.getenv("ALERT_SIGNING_KEY", "").strip()
    else:
        raw = env_value.strip()
    dev_mode = is_dev_mode() if dev is None else dev
    if raw and not is_public_default_signing_key(raw):
        return raw.encode("utf-8"), "env", None

    directory = Path(data_dir) if data_dir is not None else aegis_data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "alert_signing_key"
    warning = (
        "[AEGIS] WARNING: ALERT_SIGNING_KEY is missing or is the public example "
        f"default '{PUBLIC_DEFAULT_SIGNING_KEY}'. That value is REJECTED for HMAC triage."
    )

    if key_path.is_file():
        persisted = key_path.read_text(encoding="utf-8").strip()
        if persisted and not is_public_default_signing_key(persisted):
            return persisted.encode("utf-8"), "persisted", warning + f" Using {key_path}."

    if _insecure_default_allowed(dev_mode, allow_insecure):
        return (
            PUBLIC_DEFAULT_SIGNING_KEY.encode("utf-8"),
            "insecure-default",
            warning + " Dev override AEGIS_ALLOW_INSECURE_SIGNING_KEY is set. Do not use this outside a local experiment.",
        )

    generated = secrets.token_urlsafe(32)
    key_path.write_text(generated + "\n", encoding="utf-8")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return generated.encode("utf-8"), "generated", warning + f" Generated and stored {key_path}."


def bootstrap_signing_key() -> None:
    """Resolve the process signing key once. Safe to call again."""
    global SIGNING_KEY, SIGNING_KEY_SOURCE, SIGNING_KEY_WARNING, _bootstrapped
    if _bootstrapped:
        return
    key, source, warning = resolve_signing_key()
    SIGNING_KEY = key
    SIGNING_KEY_SOURCE = source
    SIGNING_KEY_WARNING = warning or ""
    _bootstrapped = True
    if warning:
        print(warning, file=sys.stderr)


def signing_key_text() -> str:
    bootstrap_signing_key()
    return SIGNING_KEY.decode("utf-8", errors="replace")


def signing_key_source() -> str:
    bootstrap_signing_key()
    return SIGNING_KEY_SOURCE


def signing_key_is_public_default() -> bool:
    bootstrap_signing_key()
    return SIGNING_KEY == PUBLIC_DEFAULT_SIGNING_KEY.encode("utf-8")


def assert_signing_key_ok() -> None:
    """Refuse to mint triage tokens with the published default outside an explicit dev override."""
    if not signing_key_is_public_default():
        return
    if _insecure_default_allowed(is_dev_mode(), None):
        return
    raise RuntimeError(
        "Refusing HMAC triage with the public default ALERT_SIGNING_KEY. "
        "Set a unique ALERT_SIGNING_KEY or let Aegis generate ~/.aegis/alert_signing_key."
    )


bootstrap_signing_key()


def generate_triage_token(alert_id: str, contact_id: str, ttl_seconds: int = 900) -> str:
    """
    Generates a cryptographically signed, short-lived (default 15 minutes)
    HMAC-SHA256 URL-safe token allowing zero-trust access to an alert triage view.
    """
    assert_signing_key_ok()
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
