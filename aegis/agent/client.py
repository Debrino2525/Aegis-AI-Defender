"""Enroll and heartbeat against a console. Writes certs under ~/.aegis/agent/."""

from __future__ import annotations

import base64
import json
import os
import secrets
import signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import httpx

from aegis.agent.collect import collect_telemetry
from aegis.fleet.certs import load_key, sign_heartbeat
from aegis.runtime import aegis_data_dir


def agent_dir() -> Path:
    override = os.getenv("AEGIS_AGENT_DIR", "").strip()
    path = Path(override).expanduser() if override else aegis_data_dir() / "agent"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _chmod600(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


def identity_paths(root: Optional[Path] = None) -> Dict[str, Path]:
    base = root or agent_dir()
    return {
        "ca": base / "ca.crt",
        "cert": base / "client.crt",
        "key": base / "client.key",
        "meta": base / "agent.json",
    }


def load_identity(root: Optional[Path] = None) -> Dict[str, Any]:
    paths = identity_paths(root)
    missing = [str(p) for p in paths.values() if not p.is_file()]
    if missing:
        raise FileNotFoundError(
            "Agent is not enrolled. Missing: " + ", ".join(missing)
            + ". Run: python -m aegis.agent enroll --url URL --token TOKEN"
        )
    meta = json.loads(paths["meta"].read_text(encoding="utf-8"))
    meta["certificate_pem"] = paths["cert"].read_text(encoding="utf-8")
    meta["private_key_pem"] = paths["key"].read_text(encoding="utf-8")
    meta["ca_pem"] = paths["ca"].read_text(encoding="utf-8")
    return meta


def save_identity(payload: Dict[str, Any], console_url: str, root: Optional[Path] = None) -> Path:
    base = root or agent_dir()
    paths = identity_paths(base)
    paths["ca"].write_text(payload["ca_pem"], encoding="utf-8")
    paths["cert"].write_text(payload["certificate_pem"], encoding="utf-8")
    paths["key"].write_text(payload["private_key_pem"], encoding="utf-8")
    _chmod600(paths["key"])
    _chmod600(paths["cert"])
    meta = {
        "agent_id": payload["agent_id"],
        "console_url": console_url.rstrip("/"),
        "cert_fingerprint": payload.get("cert_fingerprint"),
        "enrolled_at": payload.get("enrolled_at"),
        "heartbeat_path": payload.get("heartbeat_path") or "/api/fleet/heartbeat",
    }
    paths["meta"].write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    _chmod600(paths["meta"])
    return base


def _httpx_kwargs(
    timeout: float,
    ca_path: Optional[Path] = None,
    client_paths: Optional[Dict[str, Path]] = None,
    use_client_cert: bool = False,
) -> Dict[str, Any]:
    # httpx 0.28 ignores cert= when verify is a file path. Load both onto one SSLContext.
    import ssl

    kwargs: Dict[str, Any] = {"timeout": timeout}
    ctx: Optional[ssl.SSLContext] = None
    if ca_path is not None and ca_path.is_file():
        ctx = ssl.create_default_context(cafile=str(ca_path))
    if use_client_cert and client_paths:
        cert = client_paths.get("cert")
        key = client_paths.get("key")
        if cert is not None and key is not None and cert.is_file() and key.is_file():
            if ctx is None:
                ctx = ssl.create_default_context()
            ctx.load_cert_chain(str(cert), str(key))
    if ctx is not None:
        kwargs["verify"] = ctx
    return kwargs


def _ca_hint(exc: BaseException, console_url: str) -> str:
    return (
        f"{exc}. If the console uses the site CA for HTTPS, copy "
        "~/.aegis/ca/ca.crt from the console host and pass --ca PATH "
        f"(url was {console_url})."
    )


def enroll(
    console_url: str,
    token: str,
    root: Optional[Path] = None,
    timeout: float = 20.0,
    ca: Optional[str] = None,
) -> Dict[str, Any]:
    telemetry = collect_telemetry()
    url = urljoin(console_url.rstrip("/") + "/", "api/fleet/enroll")
    body = {
        "token": token,
        "hostname": telemetry.get("hostname") or "unknown-host",
        "os_name": telemetry.get("os_name") or "",
        "os_version": telemetry.get("os_version") or "",
        "arch": telemetry.get("arch") or "",
        "agent_version": telemetry.get("agent_version") or "",
    }
    ca_path = Path(ca).expanduser() if ca else None
    try:
        with httpx.Client(**_httpx_kwargs(timeout, ca_path=ca_path)) as client:
            response = client.post(url, json=body)
    except httpx.RequestError as exc:
        raise RuntimeError(_ca_hint(exc, console_url)) from exc
    if response.status_code >= 400:
        detail = _detail(response)
        raise RuntimeError(f"Enroll failed ({response.status_code}): {detail}")
    payload = response.json()
    save_identity(payload, console_url, root=root)
    return payload


def heartbeat(root: Optional[Path] = None, timeout: float = 20.0) -> Dict[str, Any]:
    identity = load_identity(root)
    telemetry = collect_telemetry()
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = secrets.token_urlsafe(16)
    key = load_key(identity["private_key_pem"])
    signature = sign_heartbeat(key, identity["agent_id"], timestamp, nonce)
    body = {
        "agent_id": identity["agent_id"],
        "timestamp": timestamp,
        "nonce": nonce,
        "certificate_pem": identity["certificate_pem"],
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "telemetry": telemetry,
    }
    path = identity.get("heartbeat_path") or "/api/fleet/heartbeat"
    url = urljoin(identity["console_url"].rstrip("/") + "/", path.lstrip("/"))
    paths = identity_paths(root)
    use_client_cert = str(identity.get("console_url") or "").lower().startswith("https://")
    try:
        with httpx.Client(
            **_httpx_kwargs(
                timeout,
                ca_path=paths["ca"],
                client_paths=paths,
                use_client_cert=use_client_cert,
            )
        ) as client:
            response = client.post(url, json=body)
    except httpx.RequestError as exc:
        raise RuntimeError(_ca_hint(exc, identity.get("console_url") or url)) from exc
    if response.status_code >= 400:
        raise RuntimeError(f"Heartbeat failed ({response.status_code}): {_detail(response)}")
    return response.json()


def run_loop(interval: float = 30.0, root: Optional[Path] = None) -> None:
    stop = {"value": False}

    def _stop(_signum: int, _frame: Any) -> None:
        stop["value"] = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass

    backoff = 5.0
    while not stop["value"]:
        started = time.monotonic()
        try:
            result = heartbeat(root=root)
            print(
                f"[AEGIS-AGENT] heartbeat ok agent={result.get('agent_id')} "
                f"status={result.get('status')}",
                flush=True,
            )
            backoff = 5.0
            sleep_for = max(1.0, interval - (time.monotonic() - started))
        except Exception as exc:
            print(f"[AEGIS-AGENT] heartbeat error: {exc}", flush=True)
            sleep_for = backoff
            backoff = min(60.0, backoff * 2)
        deadline = time.monotonic() + sleep_for
        while not stop["value"] and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))


def _detail(response: httpx.Response) -> str:
    try:
        data = response.json()
        if isinstance(data, dict) and data.get("detail"):
            return str(data["detail"])
    except Exception:
        pass
    return (response.text or "")[:400]
