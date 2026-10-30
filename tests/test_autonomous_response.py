"""Auditable host response: Observe / Recommend / Auto, fleet contain, no fake blocks."""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from aegis.agent.contain import execute_commands
from aegis.fleet.certs import load_key, sign_heartbeat
from aegis.fleet.service import reset_fleet_service
from aegis.response.audit import verify_audit
from aegis.response.engine import get_response_engine, reset_response_engine
from aegis.response.executor import HostExecutor
from server import analyst, app, monitor, scans

ROOT = Path(__file__).resolve().parents[1]


class FakeExecutor:
    def __init__(self):
        self.calls: List[Dict[str, Any]] = []
        self.blocked = set()
        self.quarantined = set()

    def apply(self, action: str, target: str, action_id: str = "", dry_run: bool = False) -> Dict[str, Any]:
        self.calls.append({"action": action, "target": target, "dry_run": dry_run, "action_id": action_id})
        if dry_run:
            return {
                "action": action,
                "target": target,
                "applied": False,
                "success": False,
                "dry_run": True,
                "mutates": False,
                "would": f"Would {action} {target}",
                "commands": [f"{action} {target}"],
            }
        if action == "block_ip":
            self.blocked.add(target)
        elif action == "unblock_ip":
            self.blocked.discard(target)
        elif action == "quarantine_host":
            self.quarantined.add(target)
        elif action == "unquarantine_host":
            self.quarantined.discard(target)
        return {
            "action": action,
            "target": target,
            "applied": True,
            "success": True,
            "dry_run": False,
            "message": f"Applied {action} {target}",
        }

    def rollback(self, action: str, target: str, action_id: str = "", dry_run: bool = False) -> Dict[str, Any]:
        inverse = {"block_ip": "unblock_ip", "quarantine_host": "unquarantine_host"}.get(action)
        if not inverse:
            return {"applied": False, "success": False, "error": "not reversible"}
        return self.apply(inverse, target, action_id=action_id, dry_run=dry_run)


@pytest.fixture
def client():
    reset_fleet_service(clear=True)
    reset_response_engine(clear=True)
    engine = get_response_engine()
    fake = FakeExecutor()
    engine.executor = fake
    with TestClient(app) as test_client:
        monitor.current_connections = []
        monitor.alerts = []
        monitor.conn_history = defaultdict(list)
        analyst.clear()
        scans.clear()
        test_client.fake = fake  # type: ignore[attr-defined]
        yield test_client
    monitor.current_connections = []
    monitor.alerts = []
    monitor.conn_history = defaultdict(list)
    analyst.clear()
    scans.clear()
    reset_fleet_service(clear=True)
    reset_response_engine(clear=True)


def _auth():
    return {"Authorization": f"Bearer {os.environ['AEGIS_ADMIN_TOKEN']}"}


def _sign(private_key_pem, agent_id, timestamp, nonce):
    import base64
    signature = sign_heartbeat(load_key(private_key_pem), agent_id, timestamp, nonce)
    return base64.b64encode(signature).decode("ascii")


def _enroll_heartbeat(client, hostname="app-01.corp.example", ipv4="10.20.0.14"):
    minted = client.post("/api/fleet/tokens", headers=_auth(), json={"label": "lab"})
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
    payload = enroll.json()
    agent_id = payload["agent_id"]
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = "nonce-rsp-" + agent_id[-8:]
    beat = client.post(
        "/api/fleet/heartbeat",
        json={
            "agent_id": agent_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "certificate_pem": payload["certificate_pem"],
            "signature_b64": _sign(payload["private_key_pem"], agent_id, timestamp, nonce),
            "telemetry": {"hostname": hostname, "ipv4": [ipv4], "os_name": "Linux"},
        },
    )
    assert beat.status_code == 200, beat.text
    payload["ipv4"] = ipv4
    return payload


def _c2_incident(client, src="10.20.0.14", dest="198.51.100.9"):
    monitor.alerts = [{
        "id": "ALT-RSP-1",
        "pattern_id": "AEGIS-BEH-002",
        "severity": "HIGH",
        "title": "C2 beacon",
        "source_ip": src,
        "dest_ip": dest,
        "dest_port": 443,
        "process": "svc.exe",
        "tactic": "Command and Control",
        "technique": "T1071",
        "timestamp": "2026-10-30T21:00:00+00:00",
        "_timestamp": 10.0,
        "acknowledged": False,
    }]
    monitor.current_connections = [{
        "local_ip": src,
        "remote_ip": dest,
        "remote_port": 443,
        "status": "ESTABLISHED",
        "process": "svc.exe",
        "pid": 44,
    }]
    res = client.get("/api/monitor", headers=_auth())
    assert res.status_code == 200
    incidents = res.json()["incidents"]
    assert incidents
    return incidents[0]


def test_response_apis_require_auth(client):
    assert client.get("/api/response/policy").status_code == 401
    assert client.get("/api/response/actions").status_code == 401
    assert client.post("/api/response/preview", json={"action": "block_ip", "target": "1.2.3.4"}).status_code == 401
    assert client.post("/api/response/confirm", json={"action_id": "act_x", "confirm": True}).status_code == 401
    assert client.post("/api/response/rollback", json={"action_id": "act_x", "confirm": True}).status_code == 401
    assert client.post("/api/response/assets/console", json={"mode": "observe"}).status_code == 401


def test_new_site_defaults_to_recommend_not_auto(client):
    res = client.get("/api/response/policy", headers=_auth())
    assert res.status_code == 200
    body = res.json()
    assert body["site_mode"] == "recommend"
    assert body["auto_allowed"] is False
    assert body["ceiling"] == "recommend"
    denied = client.post(
        "/api/response/policy",
        headers=_auth(),
        json={"site_mode": "auto", "auto_allowed": True, "confirm_auto": False},
    )
    assert denied.status_code == 400
    still = client.get("/api/response/policy", headers=_auth()).json()
    assert still["auto_allowed"] is False
    assert still["site_mode"] == "recommend"
    asset = client.post(
        "/api/response/assets/agt_demo",
        headers=_auth(),
        json={"mode": "auto"},
    )
    assert asset.status_code == 400


def test_observe_records_and_does_not_execute(client):
    _c2_incident(client, src="127.0.0.1")
    client.post("/api/response/assets/console", headers=_auth(), json={"mode": "observe"})
    inc = client.get("/api/monitor", headers=_auth()).json()["incidents"][0]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "block_ip", "target": "198.51.100.9"},
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["rule_id"]
    assert body["dry_run"]["mutates"] is False
    assert body["evidence"]["alert_ids"]
    assert verify_audit(body["audit"])
    confirmed = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": body["action_id"], "confirm": True},
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "observed"
    assert confirmed.json()["applied"] is False
    assert client.fake.blocked == set()


def test_recommend_requires_confirm_and_signs_audit(client):
    _c2_incident(client, src="127.0.0.1")
    inc = client.get("/api/monitor", headers=_auth()).json()["incidents"][0]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "block_ip", "target": "198.51.100.9"},
    ).json()
    assert preview["mode"] == "recommend"
    assert preview["status"] == "preview"
    assert preview["applied"] is False
    skipped = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": preview["action_id"], "confirm": False},
    )
    assert skipped.status_code == 400
    assert "198.51.100.9" not in client.fake.blocked
    done = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": preview["action_id"], "confirm": True},
    )
    assert done.status_code == 200, done.text
    body = done.json()
    assert body["applied"] is True
    assert body["status"] == "executed"
    assert verify_audit(body["audit"])
    audit = client.get(f"/api/response/actions/{body['action_id']}/audit", headers=_auth())
    assert audit.status_code == 200
    assert audit.json()["verified"] is True
    assert "198.51.100.9" in client.fake.blocked


def test_rollback_unblocks(client):
    _c2_incident(client, src="127.0.0.1")
    inc = client.get("/api/monitor", headers=_auth()).json()["incidents"][0]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "block_ip", "target": "198.51.100.9"},
    ).json()
    executed = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": preview["action_id"], "confirm": True},
    ).json()
    assert executed["applied"] is True
    rolled = client.post(
        "/api/response/rollback",
        headers=_auth(),
        json={"action_id": executed["action_id"], "confirm": True},
    )
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["applied"] is True
    assert rolled.json()["action"] == "unblock_ip"
    assert "198.51.100.9" not in client.fake.blocked


def test_no_agent_does_not_fake_console_block(client):
    _c2_incident(client, src="203.0.113.50")
    inc = client.get("/api/monitor", headers=_auth()).json()["incidents"][0]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "block_ip", "target": "198.51.100.9"},
    ).json()
    assert preview["reachable"] is False
    confirmed = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": preview["action_id"], "confirm": True},
    )
    body = confirmed.json()
    assert body["applied"] is False
    assert body["status"] == "failed"
    assert "not applied" in (body.get("error") or "").lower()
    assert client.fake.blocked == set()


def test_fleet_contain_goes_to_agent_not_console(client):
    payload = _enroll_heartbeat(client)
    _c2_incident(client, src="10.20.0.14")
    inc = client.get("/api/monitor", headers=_auth()).json()["incidents"][0]
    assert inc["response"]["asset_id"] == payload["agent_id"]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "block_ip", "target": "198.51.100.9"},
    ).json()
    confirmed = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": preview["action_id"], "confirm": True},
    ).json()
    assert confirmed["status"] == "queued"
    assert confirmed["applied"] is False
    assert confirmed["asset_id"] == payload["agent_id"]
    assert client.fake.blocked == set()

    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = "nonce-cmd-" + payload["agent_id"][-6:]
    beat = client.post(
        "/api/fleet/heartbeat",
        json={
            "agent_id": payload["agent_id"],
            "timestamp": timestamp,
            "nonce": nonce,
            "certificate_pem": payload["certificate_pem"],
            "signature_b64": _sign(payload["private_key_pem"], payload["agent_id"], timestamp, nonce),
            "telemetry": {"hostname": "app-01.corp.example", "ipv4": ["10.20.0.14"]},
        },
    )
    assert beat.status_code == 200, beat.text
    commands = beat.json().get("commands") or []
    assert commands
    assert commands[0]["kind"] == "block_ip"
    assert commands[0]["target"] == "198.51.100.9"
    assert commands[0]["rule_id"]

    results = execute_commands(commands, executor=client.fake)
    assert results[-1]["applied"] is True
    timestamp2 = datetime.now(timezone.utc).isoformat()
    nonce2 = "nonce-res-" + payload["agent_id"][-6:]
    done = client.post(
        "/api/fleet/heartbeat",
        json={
            "agent_id": payload["agent_id"],
            "timestamp": timestamp2,
            "nonce": nonce2,
            "certificate_pem": payload["certificate_pem"],
            "signature_b64": _sign(payload["private_key_pem"], payload["agent_id"], timestamp2, nonce2),
            "telemetry": {"hostname": "app-01.corp.example", "ipv4": ["10.20.0.14"]},
            "command_results": results,
        },
    )
    assert done.status_code == 200, done.text
    action = client.get(f"/api/response/actions/{confirmed['action_id']}", headers=_auth()).json()
    assert action["status"] == "executed"
    assert action["applied"] is True
    assert "198.51.100.9" in client.fake.blocked


def test_auto_does_not_fire_until_site_armed(client):
    _c2_incident(client, src="127.0.0.1")
    actions = client.get("/api/response/actions", headers=_auth()).json()["actions"]
    assert actions == []
    armed = client.post(
        "/api/response/policy",
        headers=_auth(),
        json={"site_mode": "auto", "auto_allowed": True, "confirm_auto": True},
    )
    assert armed.status_code == 200, armed.text
    assert armed.json()["auto_allowed"] is True
    client.post("/api/response/assets/console", headers=_auth(), json={"mode": "auto"})
    _c2_incident(client, src="127.0.0.1")
    actions = client.get("/api/response/actions", headers=_auth()).json()["actions"]
    assert actions
    assert any(row.get("confirmed_by") == "auto" for row in actions)
    assert "198.51.100.9" in client.fake.blocked


def test_linux_executor_does_not_fake_a_block(monkeypatch):
    monkeypatch.setenv("AEGIS_CONTAIN_PLATFORM", "linux")

    def fail(command, timeout=8.0):
        return {"command": command, "ok": False, "returncode": 1, "stderr": "Permission denied", "stdout": ""}

    monkeypatch.setattr("aegis.response.executor._run_shell", fail)
    result = HostExecutor().apply("block_ip", "198.51.100.9", dry_run=False)
    assert result["applied"] is False
    assert result["success"] is False
    assert "not applied" in (result.get("error") or "").lower()
    preview = HostExecutor().apply("block_ip", "198.51.100.9", dry_run=True)
    assert preview["applied"] is False
    assert preview["dry_run"] is True


def test_ui_has_modes_and_no_antigena():
    index = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    incident_js = (ROOT / "static" / "incident.js").read_text(encoding="utf-8")
    incident_html = (ROOT / "static" / "incident.html").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for blob in (index, incident_js, incident_html, readme):
        assert "Antigena" not in blob
        assert "Inoculation" not in blob
    assert "Observe" in index
    assert "Recommend" in index
    assert "Host response" in index
    assert "/api/response/preview" in incident_js
    assert "/api/response/confirm" in incident_js
    assert "/api/response/rollback" in incident_js
    assert "signed" in incident_js.lower() or "Signed audit" in incident_js
    assert "Preview &amp; confirm" in index or "Preview & confirm" in index
