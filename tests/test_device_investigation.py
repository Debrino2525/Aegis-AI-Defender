"""Device investigation: real samples only, Trusted Night, contain dry-run."""

import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from aegis.fleet.certs import load_key, sign_heartbeat
from aegis.fleet.service import reset_fleet_service
from aegis.investigate.device import DeviceSources, build_investigation, list_investigations
from aegis.monitor.network_monitor import NetworkMonitor
from aegis.monitor.remediation import preview_contain_action, remediator
from server import analyst, app, monitor, scans

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(monkeypatch):
    reset_fleet_service(clear=True)

    async def _noop(self):
        return None

    monkeypatch.setattr(NetworkMonitor, "_sample_connections", _noop)
    with TestClient(app) as test_client:
        monitor.current_connections = []
        monitor.alerts = []
        monitor.conn_history = defaultdict(list)
        analyst.clear()
        scans.clear()
        yield test_client
    monitor.current_connections = []
    monitor.alerts = []
    monitor.conn_history = defaultdict(list)
    analyst.clear()
    scans.clear()
    reset_fleet_service(clear=True)


def _auth_header():
    return {"Authorization": f"Bearer {os.environ['AEGIS_ADMIN_TOKEN']}"}


def _sign(private_key_pem, agent_id, timestamp, nonce):
    import base64
    signature = sign_heartbeat(load_key(private_key_pem), agent_id, timestamp, nonce)
    return base64.b64encode(signature).decode("ascii")


def _enroll_heartbeat(client, hostname="app-01.corp.example", ipv4="10.20.0.14"):
    minted = client.post("/api/fleet/tokens", headers=_auth_header(), json={"label": "lab"})
    token = minted.json()["token"]
    enroll = client.post(
        "/api/fleet/enroll",
        json={
            "token": token,
            "hostname": hostname,
            "os_name": "Linux",
            "os_version": "6.8.0",
            "arch": "x86_64",
            "agent_version": "1.0.0",
        },
    )
    payload = enroll.json()
    agent_id = payload["agent_id"]
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = "nonce-invest-" + agent_id[-8:]
    beat = client.post(
        "/api/fleet/heartbeat",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "certificate_pem": payload["certificate_pem"],
            "signature_b64": _sign(payload["private_key_pem"], agent_id, timestamp, nonce),
            "telemetry": {
                "hostname": hostname,
                "os_name": "Linux",
                "arch": "x86_64",
                "ipv4": [ipv4],
                "listen_count": 1,
                "listening_tcp": [{"ip": "0.0.0.0", "port": 443}],
                "connection_count": 4,
                "process_count": 88,
            },
        },
    )
    assert beat.status_code == 200, beat.text
    return agent_id


def _assert_claims_have_samples(body):
    assert body["claims"]
    for claim in body["claims"]:
        assert claim["sample_id"]
        assert claim["sample"]
        assert claim["sample"]["id"] == claim["sample_id"]
        assert claim["sample"]["kind"]
        assert claim["text"]


def test_investigations_require_trusted_night(client):
    assert client.get("/api/investigations").status_code == 401
    assert client.get("/api/investigations?ip=10.20.0.14").status_code == 401
    denied = client.post(
        "/api/investigations/ip:10.20.0.14/contain",
        json={"action": "block_ip", "target": "1.2.3.4", "dry_run": True},
    )
    assert denied.status_code == 401


def test_page_is_device_first_and_not_darktrace(client):
    page = client.get("/investigate")
    assert page.status_code == 200
    text = page.text
    assert "Device investigation" in text
    assert "Unlock Aegis" in text
    assert "/static/investigate.js" in text
    assert "Antigena" not in text
    assert "Patterns of Life" not in text
    assert "Inoculation" not in text
    assert "--dt-magenta" not in text
    assert "world_map.svg" not in text
    script = client.get("/static/investigate.js")
    assert script.status_code == 200
    body = script.text
    assert "/api/auth/login" in body
    assert "/api/investigations" in body
    assert "dry_run: true" in body
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert 'href="/investigate"' in html
    assert "Investigate" in html


def test_enrolled_host_opens_one_investigation(client):
    agent_id = _enroll_heartbeat(client)
    listed = client.get("/api/investigations", headers=_auth_header())
    assert listed.status_code == 200
    rows = listed.json()["investigations"]
    match = [row for row in rows if row.get("agent_id") == agent_id]
    assert len(match) == 1
    row = match[0]
    assert row["kind"] == "enrolled_host"
    assert row["id"] == f"host:{agent_id}"
    assert "10.20.0.14" in row["addresses"]

    detail = client.get(f"/api/investigations?host={agent_id}", headers=_auth_header())
    assert detail.status_code == 200
    body = detail.json()
    assert body["id"] == f"host:{agent_id}"
    assert body["device"]["kind"] == "enrolled_host"
    assert body["device"]["sample"]["kind"] == "agent_telemetry"
    assert body["device"]["sample"]["id"] == agent_id
    _assert_claims_have_samples(body)
    kinds = {item["kind"] for item in body["timeline"]}
    assert "agent_telemetry" in kinds
    assert "listen" in kinds
    assert not any(item["kind"] == "socket" for item in body["timeline"])
    assert "No live monitor socket sample matches this host." in body["gaps"]
    assert "demo-host" not in str(body)
    assert "sample-dc01" not in str(body)


def test_source_ip_timeline_from_real_monitor_and_scan(client):
    src = "203.0.113.50"
    dst = "198.51.100.9"
    monitor.current_connections = [
        {
            "local_ip": src,
            "remote_ip": dst,
            "remote_port": 445,
            "status": "ESTABLISHED",
            "pid": 4242,
            "process": "malware.exe",
            "is_internal": False,
            "port_label": "",
            "timestamp": "2026-10-30T21:00:00+00:00",
        }
    ]
    monitor.alerts = [
        {
            "id": "ALT-0401",
            "pattern_id": "AEGIS-BEH-010",
            "severity": "CRITICAL",
            "title": "SMB Lateral Movement from 203.0.113.50",
            "description": "Host made SMB connections.",
            "source_ip": src,
            "dest_ip": dst,
            "dest_port": 445,
            "process": "malware.exe",
            "evidence": f"SMB (port 445) {src} → {dst}",
            "tactic": "Lateral Movement",
            "technique": "T1021.002",
            "timestamp": "2026-10-30T21:00:01+00:00",
            "acknowledged": False,
        }
    ]
    scans["SCANINV1"] = {
        "id": "SCANINV1",
        "target": src,
        "status": "done",
        "started_at": "2026-10-30T20:59:00+00:00",
        "duration": 1.1,
        "total_findings": 1,
        "severity_breakdown": {"HIGH": 1},
        "open_ports": [445],
        "findings": [
            {
                "id": "AEGIS-SMB-001",
                "title": "SMB signing not required",
                "target": src,
                "port": 445,
                "severity": "HIGH",
                "evidence": "SMB signing disabled on 203.0.113.50:445",
                "cve_id": None,
            }
        ],
    }

    listed = client.get("/api/investigations", headers=_auth_header())
    ids = [row["id"] for row in listed.json()["investigations"]]
    assert f"ip:{src}" in ids

    body = client.get(f"/api/investigations?ip={src}", headers=_auth_header()).json()
    assert body["device"]["kind"] == "source_ip"
    kinds = {item["kind"] for item in body["timeline"]}
    assert "socket" in kinds
    assert "alert" in kinds
    assert "finding" in kinds
    assert "scan" in kinds
    _assert_claims_have_samples(body)
    related_ids = [alert["id"] for alert in body["related_alerts"]]
    assert "ALT-0401" in related_ids
    sample_ids = {item["id"] for item in body["timeline"]}
    for claim in body["claims"]:
        assert claim["sample_id"] in sample_ids or claim["sample"]["kind"] in {
            "socket", "alert", "finding", "scan", "agent_telemetry", "listen", "flow"
        }
    assert body["contain"]["mode"] == "dry_run"
    assert body["contain"]["mutates"] is False
    actions = {f"{row['action']}:{row['target']}" for row in body["contain"]["actions"] if row.get("success")}
    assert "block_ip:198.51.100.9" in actions
    assert "isolate_connections:198.51.100.9" in actions
    assert "terminate_process:malware.exe" in actions
    for row in body["contain"]["actions"]:
        if row.get("success"):
            assert row["evidence_sample_id"]
            assert row["dry_run"] is True
            assert row["mutates"] is False


def test_unknown_agent_is_404_not_a_fake_host(client):
    missing = client.get("/api/investigations?host=agt_missing", headers=_auth_header())
    assert missing.status_code == 404
    empty_ip = client.get("/api/investigations?ip=203.0.113.250", headers=_auth_header())
    assert empty_ip.status_code == 200
    body = empty_ip.json()
    assert body["timeline"] == []
    assert body["related_alerts"] == []
    assert body["contain"]["actions"] == []
    assert any("No live monitor socket" in gap for gap in body["gaps"])


def test_contain_dry_run_does_not_execute(client, monkeypatch):
    src = "203.0.113.51"
    dst = "198.51.100.10"
    monitor.current_connections = [
        {
            "local_ip": src,
            "remote_ip": dst,
            "remote_port": 4444,
            "status": "ESTABLISHED",
            "pid": 99,
            "process": "beacon.exe",
            "timestamp": "2026-10-30T21:10:00+00:00",
        }
    ]

    def _fail(*_args, **_kwargs):
        raise AssertionError("containment execute path must not run during dry-run")

    monkeypatch.setattr(remediator, "terminate_process", _fail)
    monkeypatch.setattr(remediator, "block_remote_ip", _fail)
    monkeypatch.setattr(remediator, "isolate_socket_connections", _fail)

    preview = client.post(
        f"/api/investigations/{quote('ip:' + src, safe='')}/contain",
        headers=_auth_header(),
        json={"action": "block_ip", "target": dst, "dry_run": True},
    )
    assert preview.status_code == 200
    data = preview.json()
    assert data["dry_run"] is True
    assert data["mutates"] is False
    assert data["success"] is True
    assert dst in data["would"]
    assert data["commands"]
    assert "netsh" in data["commands"][0]

    forbidden = client.post(
        f"/api/investigations/ip:{src}/contain",
        headers=_auth_header(),
        json={"action": "block_ip", "target": dst, "dry_run": False},
    )
    assert forbidden.status_code == 400


def test_preview_helper_never_mutates():
    result = preview_contain_action("block_ip", "198.51.100.20")
    assert result["dry_run"] is True
    assert result["mutates"] is False
    assert result["success"] is True
    protected = preview_contain_action("terminate_process", "lsass.exe")
    assert protected["success"] is False


def test_assembler_rejects_unrelated_events():
    sources = DeviceSources(
        connections=[
            {
                "local_ip": "10.0.0.8",
                "remote_ip": "10.0.0.9",
                "remote_port": 22,
                "pid": 1,
                "process": "ssh",
                "timestamp": "2026-10-30T00:00:00+00:00",
            }
        ],
        monitor_alerts=[
            {
                "id": "ALT-9999",
                "title": "Other host",
                "source_ip": "10.0.0.8",
                "dest_ip": "10.0.0.9",
                "timestamp": "2026-10-30T00:00:01+00:00",
            }
        ],
        scans=[
            {
                "id": "SCANOTHER",
                "target": "10.0.0.8",
                "status": "done",
                "findings": [{"id": "F9", "title": "Other", "target": "10.0.0.8", "severity": "LOW"}],
            }
        ],
    )
    body = build_investigation(sources, "ip:203.0.113.80")
    assert body is not None
    assert body["timeline"] == []
    assert body["claims"] == []
    assert body["related_alerts"] == []
    listed = list_investigations(sources)
    ids = [row["id"] for row in listed["investigations"]]
    assert "ip:10.0.0.8" in ids
    assert "ip:203.0.113.80" not in ids
