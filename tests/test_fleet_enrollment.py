"""Enroll, heartbeat, and empty Assets — real tokens and certs, no fake hosts."""

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.agent.collect import collect_telemetry
from aegis.fleet.certs import load_key, sign_heartbeat
from aegis.fleet.service import reset_fleet_service
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


def test_assets_empty_without_heartbeats(client):
    assert client.get("/api/fleet/hosts").status_code == 401
    assert client.get("/api/fleet/status").status_code == 401
    res = client.get("/api/fleet/hosts", headers=_auth_header())
    assert res.status_code == 200
    body = res.json()
    assert body == {"hosts": []}
    intel = client.get("/api/intelligence", headers=_auth_header())
    assert intel.status_code == 200
    assert intel.json()["hosts"] == []
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert "No hosts have enrolled a heartbeat" in html
    assert "sample-dc01" not in html
    assert "demo-host" not in html
    assert "revokeFleetHost" in html
    assert "reenrollFleetHost" in html
    assert "AEGIS_TLS" in html


def test_enroll_requires_token_not_admin_session(client):
    denied = client.post(
        "/api/fleet/enroll",
        json={"token": "nope", "hostname": "web-01"},
    )
    assert denied.status_code == 401
    missing = client.post("/api/fleet/enroll", json={"hostname": "web-01", "token": ""})
    assert missing.status_code in (401, 422)


def test_one_time_enroll_heartbeat_lists_real_host(client):
    minted = client.post("/api/fleet/tokens", headers=_auth_header(), json={"label": "lab"})
    assert minted.status_code == 200
    token = minted.json()["token"]
    assert token
    assert "..." not in token

    enroll = client.post(
        "/api/fleet/enroll",
        json={
            "token": token,
            "hostname": "app-01.corp.example",
            "os_name": "Linux",
            "os_version": "6.8.0",
            "arch": "x86_64",
            "agent_version": "1.0.0",
        },
    )
    assert enroll.status_code == 200
    payload = enroll.json()
    agent_id = payload["agent_id"]
    assert agent_id.startswith("agt_")
    assert "BEGIN CERTIFICATE" in payload["certificate_pem"]
    assert "BEGIN" in payload["private_key_pem"]
    assert "BEGIN CERTIFICATE" in payload["ca_pem"]

    still_empty = client.get("/api/fleet/hosts", headers=_auth_header())
    assert still_empty.json()["hosts"] == []

    reused = client.post(
        "/api/fleet/enroll",
        json={"token": token, "hostname": "app-02.corp.example"},
    )
    assert reused.status_code == 401

    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = "nonce-one-abcdefghijklmnopqrstuv"
    beat = client.post(
        "/api/fleet/heartbeat",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "certificate_pem": payload["certificate_pem"],
            "signature_b64": _sign(payload["private_key_pem"], agent_id, timestamp, nonce),
            "telemetry": {
                "hostname": "app-01.corp.example",
                "os_name": "Linux",
                "arch": "x86_64",
                "ipv4": ["10.20.0.14"],
                "listen_count": 2,
                "listening_tcp": [{"ip": "0.0.0.0", "port": 443}],
                "cpu_percent": 4.0,
                "memory_percent": 22.0,
                "process_count": 120,
            },
        },
    )
    assert beat.status_code == 200, beat.text
    assert beat.json()["ok"] is True
    assert beat.json()["agent_id"] == agent_id

    listed = client.get("/api/fleet/hosts", headers=_auth_header())
    assert listed.status_code == 200
    hosts = listed.json()["hosts"]
    assert len(hosts) == 1
    row = hosts[0]
    assert row["hostname"] == "app-01.corp.example"
    assert row["agent_id"] == agent_id
    assert row["ipv4"] == ["10.20.0.14"]
    assert row["status"] in ("online", "stale")
    assert row["listen_count"] == 2
    assert "dc01" not in row["hostname"]

    replay = client.post(
        "/api/fleet/heartbeat",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "certificate_pem": payload["certificate_pem"],
            "signature_b64": _sign(payload["private_key_pem"], agent_id, timestamp, nonce),
            "telemetry": {"hostname": "app-01.corp.example"},
        },
    )
    assert replay.status_code == 401


def test_heartbeat_without_cert_is_rejected(client):
    minted = client.post("/api/fleet/tokens", headers=_auth_header())
    token = minted.json()["token"]
    enroll = client.post(
        "/api/fleet/enroll",
        json={"token": token, "hostname": "db-01"},
    )
    agent_id = enroll.json()["agent_id"]
    timestamp = datetime.now(timezone.utc).isoformat()
    denied = client.post(
        "/api/fleet/heartbeat",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": "nonce-no-cert",
            "certificate_pem": "not-a-cert",
            "signature_b64": "aaaa",
            "telemetry": {"hostname": "db-01"},
        },
    )
    assert denied.status_code == 401
    listed = client.get("/api/fleet/hosts", headers=_auth_header())
    assert listed.json()["hosts"] == []


def test_env_enrollment_token_is_reusable(client, monkeypatch):
    monkeypatch.setenv("AEGIS_ENROLLMENT_TOKEN", "lab-bootstrap-token-not-public")
    first = client.post(
        "/api/fleet/enroll",
        json={"token": "lab-bootstrap-token-not-public", "hostname": "win-01", "os_name": "Windows"},
    )
    second = client.post(
        "/api/fleet/enroll",
        json={"token": "lab-bootstrap-token-not-public", "hostname": "lnx-01", "os_name": "Linux"},
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["agent_id"] != second.json()["agent_id"]
    listed = client.get("/api/fleet/hosts", headers=_auth_header())
    assert listed.json()["hosts"] == []


def test_settings_masks_enrollment_token(client, monkeypatch):
    secret = "fleet-enroll-secret-value-zzzz"
    monkeypatch.setenv("AEGIS_ENROLLMENT_TOKEN", secret)
    res = client.get("/api/settings", headers=_auth_header())
    assert res.status_code == 200
    assert secret not in res.text
    fleet = res.json()["fleet"]
    assert fleet["has_env_enrollment_token"] is True
    assert fleet["enrollment_token"] != secret
    assert "..." in fleet["enrollment_token"] or fleet["enrollment_token"] == "***"
    assert fleet["ca_ready"] is True
    assert fleet["heartbeated_hosts"] == 0


def test_collect_telemetry_is_this_host(client):
    payload = collect_telemetry()
    assert payload["hostname"]
    assert payload["os_name"]
    assert "listening_tcp" in payload
    assert isinstance(payload.get("hop_connections"), list)
    assert isinstance(payload["telemetry_errors"], list)


def test_mint_token_requires_admin(client):
    assert client.post("/api/fleet/tokens").status_code == 401
    assert client.post("/api/fleet/hosts/agt_missing/revoke").status_code == 401
    assert client.post("/api/fleet/hosts/agt_missing/reenroll").status_code == 401
