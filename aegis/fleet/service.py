"""Enrollment, heartbeat verification, and host listing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from aegis.fleet.certs import SiteCA, cert_fingerprint, verify_heartbeat_signature
from aegis.fleet.store import FleetStore, get_fleet_store, reset_fleet_store
from aegis.runtime import aegis_data_dir

TOKEN_TTL_HOURS = 24
HEARTBEAT_SKEW_SECONDS = 300
ONLINE_SECONDS = 90
STALE_SECONDS = 15 * 60
NONCE_TTL_MINUTES = 10


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _secret_equal(presented: str, expected: str) -> bool:
    if not expected or presented is None:
        return False
    return hmac.compare_digest(
        hashlib.sha256(presented.encode("utf-8")).digest(),
        hashlib.sha256(expected.encode("utf-8")).digest(),
    )


def _parse_iso(value: str) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def host_status(last_seen: Optional[str], now: Optional[datetime] = None) -> str:
    if not last_seen:
        return "offline"
    current = now or _now()
    try:
        seen = _parse_iso(last_seen)
    except ValueError:
        return "offline"
    age = (current - seen).total_seconds()
    if age <= ONLINE_SECONDS:
        return "online"
    if age <= STALE_SECONDS:
        return "stale"
    return "offline"


class FleetService:
    def __init__(self, store: Optional[FleetStore] = None, ca: Optional[SiteCA] = None):
        data = aegis_data_dir()
        self.store = store or get_fleet_store()
        self.ca = ca or SiteCA(data / "ca")

    def bootstrap(self) -> None:
        self.ca.bootstrap()

    def mint_token(self, label: str = "") -> Dict[str, str]:
        self.bootstrap()
        token = secrets.token_urlsafe(32)
        token_id = "tok_" + secrets.token_urlsafe(8)
        expires = _now() + timedelta(hours=TOKEN_TTL_HOURS)
        self.store.insert_token(token_id, _hash_token(token), expires.isoformat(), label)
        return {
            "id": token_id,
            "token": token,
            "expires_at": expires.isoformat(),
            "one_time": True,
        }

    def status(self) -> Dict[str, Any]:
        self.bootstrap()
        env_set = bool(os.getenv("AEGIS_ENROLLMENT_TOKEN", "").strip())
        return {
            "ca_ready": True,
            "ca_fingerprint": self.ca.fingerprint(),
            "heartbeated_hosts": self.store.heartbeated_count(),
            "enrolled_hosts": self.store.enrolled_count(),
            "has_env_enrollment_token": env_set,
            "one_time_tokens_unused": self.store.unused_token_count(),
            "ca_dir": str(self.ca.ca_dir),
            "agent_dir": str(Path.home() / ".aegis" / "agent"),
        }

    def enroll(
        self,
        token: str,
        hostname: str,
        os_name: str = "",
        os_version: str = "",
        arch: str = "",
        agent_version: str = "",
        remote_ip: str = "",
    ) -> Dict[str, Any]:
        self.bootstrap()
        hostname = (hostname or "").strip()
        if not hostname or len(hostname) > 253:
            raise ValueError("hostname is required")
        presented = (token or "").strip()
        if not presented:
            raise PermissionError("Enrollment token required")
        kind, token_id = self._accept_token(presented)
        agent_id = "agt_" + secrets.token_urlsafe(12)
        cert_pem, key_pem, fingerprint = self.ca.issue_client(agent_id, hostname)
        enrolled_at = _now().isoformat()
        self.store.upsert_host({
            "agent_id": agent_id,
            "hostname": hostname,
            "os_name": (os_name or "")[:64],
            "os_version": (os_version or "")[:128],
            "arch": (arch or "")[:64],
            "agent_version": (agent_version or "")[:32],
            "cert_fingerprint": fingerprint,
            "cert_pem": cert_pem,
            "enrolled_at": enrolled_at,
            "last_seen": None,
            "last_telemetry_json": None,
            "remote_ip": remote_ip or None,
        })
        if kind == "once" and token_id:
            self.store.consume_token(token_id, agent_id)
        return {
            "agent_id": agent_id,
            "ca_pem": self.ca.ca_pem(),
            "certificate_pem": cert_pem,
            "private_key_pem": key_pem,
            "cert_fingerprint": fingerprint,
            "heartbeat_path": "/api/fleet/heartbeat",
            "enrolled_at": enrolled_at,
        }

    def heartbeat(
        self,
        agent_id: str,
        timestamp: str,
        nonce: str,
        certificate_pem: str,
        signature_b64: str,
        telemetry: Optional[Dict[str, Any]] = None,
        remote_ip: str = "",
    ) -> Dict[str, Any]:
        self.bootstrap()
        agent_id = (agent_id or "").strip()
        nonce = (nonce or "").strip()
        if not agent_id or not nonce or not timestamp:
            raise ValueError("agent_id, timestamp, and nonce are required")
        if len(nonce) > 128 or len(agent_id) > 64:
            raise ValueError("heartbeat identity is too long")
        try:
            seen_at = _parse_iso(timestamp)
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
        skew = abs((_now() - seen_at).total_seconds())
        if skew > HEARTBEAT_SKEW_SECONDS:
            raise PermissionError("Heartbeat timestamp is outside the allowed skew")
        cutoff = (_now() - timedelta(minutes=NONCE_TTL_MINUTES)).isoformat()
        self.store.prune_nonces(cutoff)
        if not self.store.remember_nonce(nonce):
            raise PermissionError("Heartbeat nonce was already used")
        try:
            cert = self.ca.verify_client_pem(certificate_pem)
        except Exception as exc:
            raise PermissionError("Client certificate is not trusted") from exc
        fingerprint = cert_fingerprint(cert)
        host = self.store.get_host(agent_id)
        if not host:
            raise PermissionError("Unknown agent_id")
        if host["cert_fingerprint"] != fingerprint:
            raise PermissionError("Certificate does not match this agent")
        try:
            signature = base64.b64decode(signature_b64 or "")
            verify_heartbeat_signature(cert, agent_id, timestamp, nonce, signature)
        except Exception as exc:
            raise PermissionError("Heartbeat signature is invalid") from exc
        payload = dict(telemetry or {})
        hostname = str(payload.get("hostname") or host["hostname"])[:253]
        os_name = str(payload.get("os_name") or host.get("os_name") or "")[:64]
        os_version = str(payload.get("os_version") or host.get("os_version") or "")[:128]
        arch = str(payload.get("arch") or host.get("arch") or "")[:64]
        agent_version = str(payload.get("agent_version") or host.get("agent_version") or "")[:32]
        self.store.upsert_host({
            "agent_id": agent_id,
            "hostname": hostname,
            "os_name": os_name,
            "os_version": os_version,
            "arch": arch,
            "agent_version": agent_version,
            "cert_fingerprint": fingerprint,
            "cert_pem": certificate_pem,
            "enrolled_at": host["enrolled_at"],
            "last_seen": seen_at.isoformat(),
            "last_telemetry_json": json.dumps(payload, default=str)[:65536],
            "remote_ip": remote_ip or host.get("remote_ip"),
        })
        return {
            "ok": True,
            "agent_id": agent_id,
            "status": host_status(seen_at.isoformat()),
            "last_seen": seen_at.isoformat(),
        }

    def list_hosts(self) -> Dict[str, Any]:
        rows = []
        now = _now()
        for raw in self.store.list_heartbeated_hosts():
            rows.append(self._public_host(raw, now))
        return {"hosts": rows}

    def _public_host(self, raw: Dict[str, Any], now: datetime) -> Dict[str, Any]:
        telemetry: Dict[str, Any] = {}
        blob = raw.get("last_telemetry_json") or ""
        if blob:
            try:
                parsed = json.loads(blob)
                if isinstance(parsed, dict):
                    telemetry = parsed
            except json.JSONDecodeError:
                telemetry = {}
        listening = telemetry.get("listening_tcp") or []
        if not isinstance(listening, list):
            listening = []
        ipv4 = telemetry.get("ipv4") or []
        ipv6 = telemetry.get("ipv6") or []
        return {
            "agent_id": raw["agent_id"],
            "hostname": raw.get("hostname") or "",
            "os_name": raw.get("os_name") or "",
            "os_version": raw.get("os_version") or "",
            "arch": raw.get("arch") or "",
            "agent_version": raw.get("agent_version") or "",
            "ipv4": ipv4 if isinstance(ipv4, list) else [],
            "ipv6": ipv6 if isinstance(ipv6, list) else [],
            "status": host_status(raw.get("last_seen"), now),
            "last_seen": raw.get("last_seen"),
            "enrolled_at": raw.get("enrolled_at"),
            "listen_count": telemetry.get("listen_count", len(listening)),
            "listening_tcp": listening[:64],
            "cpu_percent": telemetry.get("cpu_percent"),
            "memory_percent": telemetry.get("memory_percent"),
            "process_count": telemetry.get("process_count"),
            "connection_count": telemetry.get("connection_count"),
            "remote_ip": raw.get("remote_ip") or "",
            "telemetry_errors": telemetry.get("telemetry_errors") or [],
        }

    def _accept_token(self, presented: str) -> Tuple[str, Optional[str]]:
        row = self.store.lookup_token_hash(_hash_token(presented))
        if row:
            if row.get("used_at"):
                raise PermissionError("Enrollment token already used")
            try:
                if _parse_iso(row["expires_at"]) < _now():
                    raise PermissionError("Enrollment token expired")
            except ValueError as exc:
                raise PermissionError("Enrollment token expired") from exc
            return "once", row["id"]
        env_token = os.getenv("AEGIS_ENROLLMENT_TOKEN", "").strip()
        if env_token and _secret_equal(presented, env_token):
            return "env", None
        raise PermissionError("Invalid enrollment token")


_service: Optional[FleetService] = None


def get_fleet_service() -> FleetService:
    global _service
    if _service is None:
        _service = FleetService()
    return _service


def reset_fleet_service(clear: bool = True) -> None:
    global _service
    reset_fleet_store(clear=clear)
    _service = None
