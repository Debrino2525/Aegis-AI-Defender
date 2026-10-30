"""mTLS heartbeat, revoke/re-enroll, and service wrappers. No fake hosts."""

from __future__ import annotations

import os
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from uvicorn import Config, Server

from aegis.fleet.certs import load_key, sign_heartbeat
from aegis.fleet.service import get_fleet_service, reset_fleet_service
from aegis.fleet.tls import cert_reqs_from_env, install_peer_cert_hook, uvicorn_ssl_kwargs
from aegis.runtime import aegis_data_dir
from server import app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client():
    reset_fleet_service(clear=True)
    with TestClient(app) as test_client:
        yield test_client
    reset_fleet_service(clear=True)


def _auth_header():
    return {"Authorization": f"Bearer {os.environ['AEGIS_ADMIN_TOKEN']}"}


def _sign(private_key_pem, agent_id, timestamp, nonce):
    import base64
    signature = sign_heartbeat(load_key(private_key_pem), agent_id, timestamp, nonce)
    return base64.b64encode(signature).decode("ascii")


def _enroll(client, hostname="app-01.corp.example"):
    minted = client.post("/api/fleet/tokens", headers=_auth_header(), json={"label": "lab"})
    assert minted.status_code == 200
    token = minted.json()["token"]
    enroll = client.post(
        "/api/fleet/enroll",
        json={
            "token": token,
            "hostname": hostname,
            "os_name": "Linux",
            "arch": "x86_64",
            "agent_version": "1.0.0",
        },
    )
    assert enroll.status_code == 200, enroll.text
    return enroll.json()


def _heartbeat(client, payload, nonce, certificate_pem=None, private_key_pem=None, headers=None, extra=None):
    timestamp = datetime.now(timezone.utc).isoformat()
    cert = certificate_pem if certificate_pem is not None else payload["certificate_pem"]
    key = private_key_pem if private_key_pem is not None else payload["private_key_pem"]
    body = {
        "agent_id": payload["agent_id"],
        "timestamp": timestamp,
        "nonce": nonce,
        "certificate_pem": cert,
        "signature_b64": _sign(key, payload["agent_id"], timestamp, nonce),
        "telemetry": {"hostname": "app-01.corp.example", "ipv4": ["10.20.0.14"]},
    }
    if extra:
        body.update(extra)
    return client.post("/api/fleet/heartbeat", json=body, headers=headers or {})


def test_revoke_then_heartbeat_fails(client):
    payload = _enroll(client)
    ok = _heartbeat(client, payload, "nonce-revoke-ok-1")
    assert ok.status_code == 200, ok.text
    listed = client.get("/api/fleet/hosts", headers=_auth_header())
    assert listed.json()["hosts"][0]["hostname"] == "app-01.corp.example"

    denied = client.post(f"/api/fleet/hosts/{payload['agent_id']}/revoke")
    assert denied.status_code == 401

    revoked = client.post(
        f"/api/fleet/hosts/{payload['agent_id']}/revoke",
        headers=_auth_header(),
        json={"reason": "operator"},
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["status"] == "revoked"

    failed = _heartbeat(client, payload, "nonce-revoke-fail-2")
    assert failed.status_code == 401
    assert "revok" in failed.json()["detail"].lower()

    listed = client.get("/api/fleet/hosts", headers=_auth_header())
    row = listed.json()["hosts"][0]
    assert row["status"] == "revoked"
    assert row["revoked"] is True
    assert "sample-dc01" not in row["hostname"]


def test_reenroll_keeps_agent_id_and_kills_old_cert(client):
    payload = _enroll(client, hostname="db-01.corp.example")
    assert _heartbeat(client, payload, "nonce-re-ok-1").status_code == 200

    minted = client.post(
        f"/api/fleet/hosts/{payload['agent_id']}/reenroll",
        headers=_auth_header(),
    )
    assert minted.status_code == 200, minted.text
    token = minted.json()["token"]
    assert token
    assert minted.json()["agent_id"] == payload["agent_id"]

    old_fail = _heartbeat(client, payload, "nonce-re-old-2")
    assert old_fail.status_code == 401

    replacement = client.post(
        "/api/fleet/enroll",
        json={
            "token": token,
            "hostname": "db-01.corp.example",
            "os_name": "Linux",
        },
    )
    assert replacement.status_code == 200, replacement.text
    new_payload = replacement.json()
    assert new_payload["agent_id"] == payload["agent_id"]
    assert new_payload["certificate_pem"] != payload["certificate_pem"]
    assert new_payload["cert_fingerprint"] != payload["cert_fingerprint"]

    assert _heartbeat(client, new_payload, "nonce-re-new-3").status_code == 200
    assert _heartbeat(client, payload, "nonce-re-old-4").status_code == 401

    listed = client.get("/api/fleet/hosts", headers=_auth_header())
    hosts = listed.json()["hosts"]
    assert len(hosts) == 1
    assert hosts[0]["agent_id"] == payload["agent_id"]
    assert hosts[0]["status"] != "revoked"
    assert hosts[0]["revoked"] is False


def test_enrolled_without_heartbeat_hidden_until_seen(client):
    payload = _enroll(client, hostname="pending-01.corp.example")
    assets = client.get("/api/fleet/hosts", headers=_auth_header())
    assert assets.json() == {"hosts": []}
    all_hosts = client.get("/api/fleet/hosts?all=1", headers=_auth_header())
    assert all_hosts.status_code == 200
    rows = all_hosts.json()["hosts"]
    assert len(rows) == 1
    assert rows[0]["hostname"] == "pending-01.corp.example"
    assert rows[0]["agent_id"] == payload["agent_id"]
    assert rows[0]["last_seen"] in (None, "")


def test_proxy_header_is_cert_required_when_tls_proxy_set(client, monkeypatch):
    monkeypatch.setenv("AEGIS_TLS_PROXY", "1")
    payload = _enroll(client)
    missing = _heartbeat(client, payload, "nonce-proxy-missing")
    assert missing.status_code == 401
    assert "certificate required" in missing.json()["detail"].lower()

    headers = {
        "X-SSL-Client-Cert": payload["certificate_pem"],
        "X-SSL-Client-Verify": "SUCCESS",
    }
    ok = _heartbeat(client, payload, "nonce-proxy-ok", headers=headers)
    assert ok.status_code == 200, ok.text


def test_agent_httpx_kwargs_load_client_cert_on_ssl_context(tmp_path):
    from aegis.agent.client import _httpx_kwargs

    payload = None
    reset_fleet_service(clear=True)
    with TestClient(app) as client:
        payload = _enroll(client, hostname="ctx-01.corp.example")
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    ca = tmp_path / "ca.crt"
    cert.write_text(payload["certificate_pem"], encoding="utf-8")
    key.write_text(payload["private_key_pem"], encoding="utf-8")
    ca.write_text(payload["ca_pem"], encoding="utf-8")
    kwargs = _httpx_kwargs(
        5.0,
        ca_path=ca,
        client_paths={"cert": cert, "key": key},
        use_client_cert=True,
    )
    ctx = kwargs["verify"]
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.cert_store_stats()["x509_ca"] >= 1
    reset_fleet_service(clear=True)


def test_tls_kwargs_default_off_and_required_mode(monkeypatch):
    monkeypatch.delenv("AEGIS_TLS", raising=False)
    assert uvicorn_ssl_kwargs() == {}
    monkeypatch.setenv("AEGIS_TLS_CERT_REQS", "required")
    assert cert_reqs_from_env() == ssl.CERT_REQUIRED
    monkeypatch.setenv("AEGIS_TLS_CERT_REQS", "optional")
    assert cert_reqs_from_env() == ssl.CERT_OPTIONAL


def test_service_wrappers_stay_running_and_are_not_ghana_only():
    sh = (ROOT / "scripts" / "aegis-agent.sh").read_text(encoding="utf-8")
    unit = (ROOT / "scripts" / "aegis-agent.service").read_text(encoding="utf-8")
    bat = (ROOT / "scripts" / "aegis-agent.bat").read_text(encoding="utf-8")
    xml = (ROOT / "scripts" / "aegis-agent.winsw.xml").read_text(encoding="utf-8")
    assert "Restart=always" in unit
    assert "After=network-online.target" in unit
    assert "python3 -m aegis.agent run" in unit
    assert "install" in sh
    assert "systemctl" in sh
    assert "Restart=always" in sh
    assert "schtasks" in bat
    assert "ONSTART" in bat
    assert "aegis.agent run" in bat
    assert "winsw" in bat.lower()
    assert "aegis.agent run" in xml
    assert "<onfailure action=\"restart\"" in xml
    for text in (sh, unit, bat, xml):
        lowered = text.lower()
        assert "sample-dc01" not in lowered
        assert "arkesel" not in lowered
        assert "hubtel" not in lowered
        assert "ussd" not in lowered
        assert "ghana" not in lowered


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _ssl_client_ctx(ca_path, cert_path=None, key_path=None):
    ctx = ssl.create_default_context(cafile=str(ca_path))
    if cert_path and key_path:
        ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx


def _start_uvicorn(ssl_kwargs, port):
    install_peer_cert_hook()
    config = Config(
        app=app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
        **ssl_kwargs,
    )
    server = Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while time.time() < deadline:
        if server.started:
            return server, thread
        if not thread.is_alive():
            break
        time.sleep(0.05)
    server.should_exit = True
    thread.join(timeout=2)
    raise RuntimeError("uvicorn did not start")


def _stop_uvicorn(server, thread):
    server.should_exit = True
    thread.join(timeout=5)


def test_https_heartbeat_requires_verified_client_cert(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_TLS", "1")
    monkeypatch.setenv("AEGIS_TLS_CERT_REQS", "optional")
    reset_fleet_service(clear=True)
    get_fleet_service().bootstrap()
    ssl_kwargs = uvicorn_ssl_kwargs()
    assert ssl_kwargs["ssl_cert_reqs"] == ssl.CERT_OPTIONAL
    assert ssl_kwargs["ssl_ca_certs"]
    port = _free_port()
    server, thread = _start_uvicorn(ssl_kwargs, port)
    ca_path = aegis_data_dir() / "ca" / "ca.crt"
    base = f"https://127.0.0.1:{port}"
    try:
        with httpx.Client(verify=_ssl_client_ctx(ca_path), timeout=10.0) as http:
            minted = http.post(
                f"{base}/api/fleet/tokens",
                headers=_auth_header(),
                json={"label": "tls"},
            )
            assert minted.status_code == 200, minted.text
            enroll = http.post(
                f"{base}/api/fleet/enroll",
                json={"token": minted.json()["token"], "hostname": "tls-01.corp.example"},
            )
            assert enroll.status_code == 200, enroll.text
            payload = enroll.json()
            missing = http.post(
                f"{base}/api/fleet/heartbeat",
                json={
                    "agent_id": payload["agent_id"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "nonce": "tls-missing-cert-nonce",
                    "certificate_pem": payload["certificate_pem"],
                    "signature_b64": _sign(
                        payload["private_key_pem"],
                        payload["agent_id"],
                        datetime.now(timezone.utc).isoformat(),
                        "tls-missing-cert-nonce",
                    ),
                    "telemetry": {"hostname": "tls-01.corp.example"},
                },
            )
            assert missing.status_code == 401
            assert "certificate required" in missing.json()["detail"].lower()

            cert_path = tmp_path / "client.crt"
            key_path = tmp_path / "client.key"
            cert_path.write_text(payload["certificate_pem"], encoding="utf-8")
            key_path.write_text(payload["private_key_pem"], encoding="utf-8")
            timestamp = datetime.now(timezone.utc).isoformat()
            nonce = "tls-present-cert-nonce"
            with httpx.Client(
                verify=_ssl_client_ctx(ca_path, cert_path, key_path),
                timeout=10.0,
            ) as mtls:
                beat = mtls.post(
                    f"{base}/api/fleet/heartbeat",
                    json={
                        "agent_id": payload["agent_id"],
                        "timestamp": timestamp,
                        "nonce": nonce,
                        "certificate_pem": payload["certificate_pem"],
                        "signature_b64": _sign(
                            payload["private_key_pem"], payload["agent_id"], timestamp, nonce
                        ),
                        "telemetry": {"hostname": "tls-01.corp.example", "ipv4": ["10.9.8.7"]},
                    },
                )
            assert beat.status_code == 200, beat.text
            assert beat.json()["ok"] is True
            hosts = http.get(f"{base}/api/fleet/hosts", headers=_auth_header())
            assert hosts.status_code == 200
            rows = hosts.json()["hosts"]
            assert len(rows) == 1
            assert rows[0]["hostname"] == "tls-01.corp.example"
            assert rows[0]["ipv4"] == ["10.9.8.7"]

            revoked = http.post(
                f"{base}/api/fleet/hosts/{payload['agent_id']}/revoke",
                headers=_auth_header(),
                json={"reason": "tls-test"},
            )
            assert revoked.status_code == 200
            timestamp = datetime.now(timezone.utc).isoformat()
            nonce = "tls-revoked-cert-nonce"
            with httpx.Client(
                verify=_ssl_client_ctx(ca_path, cert_path, key_path),
                timeout=10.0,
            ) as mtls:
                dead = mtls.post(
                    f"{base}/api/fleet/heartbeat",
                    json={
                        "agent_id": payload["agent_id"],
                        "timestamp": timestamp,
                        "nonce": nonce,
                        "certificate_pem": payload["certificate_pem"],
                        "signature_b64": _sign(
                            payload["private_key_pem"], payload["agent_id"], timestamp, nonce
                        ),
                        "telemetry": {"hostname": "tls-01.corp.example"},
                    },
                )
            assert dead.status_code == 401
            assert "revok" in dead.json()["detail"].lower()
    finally:
        _stop_uvicorn(server, thread)
        reset_fleet_service(clear=True)


def test_ssl_cert_required_rejects_clients_without_a_cert(monkeypatch):
    monkeypatch.setenv("AEGIS_TLS", "1")
    monkeypatch.setenv("AEGIS_TLS_CERT_REQS", "required")
    reset_fleet_service(clear=True)
    get_fleet_service().bootstrap()
    ssl_kwargs = uvicorn_ssl_kwargs()
    assert ssl_kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    port = _free_port()
    server, thread = _start_uvicorn(ssl_kwargs, port)
    ca_path = aegis_data_dir() / "ca" / "ca.crt"
    try:
        with pytest.raises(httpx.RequestError):
            httpx.get(f"https://127.0.0.1:{port}/", verify=_ssl_client_ctx(ca_path), timeout=5.0)
    finally:
        _stop_uvicorn(server, thread)
        reset_fleet_service(clear=True)
