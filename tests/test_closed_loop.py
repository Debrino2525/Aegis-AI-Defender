"""Prevent → Detect → Respond loop: evidence only, empty when any piece is missing."""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.alerting.integrations import PROVIDERS
from aegis.alerting.router import alert_router
from aegis.assets.posture import is_verified_high_kev
from aegis.fleet.certs import load_key, sign_heartbeat
from aegis.fleet.service import reset_fleet_service
from aegis.monitor.closed_loop import EMPTY_NO_DETECT, EMPTY_NO_FINDING, EMPTY_NO_HOST
from aegis.monitor.network_monitor import NetworkMonitor
from aegis.response.audit import verify_audit
from aegis.response.engine import get_response_engine, reset_response_engine
from server import analyst, app, monitor, scans

ROOT = Path(__file__).resolve().parents[1]


class FakeExecutor:
    def __init__(self):
        self.quarantined = set()
        self.blocked = set()

    def apply(self, action, target, action_id="", dry_run=False):
        if dry_run:
            return {"action": action, "target": target, "applied": False, "dry_run": True, "mutates": False, "commands": []}
        if action == "quarantine_host":
            self.quarantined.add(target)
        if action == "block_ip":
            self.blocked.add(target)
        return {"action": action, "target": target, "applied": True, "success": True, "dry_run": False, "message": f"Applied {action}"}


@pytest.fixture
def client(monkeypatch):
    reset_fleet_service(clear=True)
    reset_response_engine(clear=True)
    engine = get_response_engine()
    fake = FakeExecutor()
    engine.executor = fake

    async def _noop(self):
        return None

    monkeypatch.setattr(NetworkMonitor, "_sample_connections", _noop)
    for provider in PROVIDERS:
        alert_router.platforms.disconnect(provider, "")
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
    for provider in PROVIDERS:
        alert_router.platforms.disconnect(provider, "")


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
    nonce = "nonce-loop-" + agent_id[-8:]
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
    payload["hostname"] = hostname
    return payload


def _scan(scan_id, target, findings, started_at="2026-10-30T20:00:00+00:00", status="done", **extra):
    payload = {
        "id": scan_id,
        "target": target,
        "status": status,
        "started_at": started_at,
        "completed_at": started_at,
        "duration": 1.2,
        "total_findings": len(findings),
        "severity_breakdown": {},
        "open_ports": extra.pop("open_ports", [443]),
        "findings": findings,
    }
    payload.update(extra)
    scans[scan_id] = payload
    return payload


def _kev_finding(target="10.20.0.14"):
    return {
        "id": "CVE-2021-44228",
        "title": "Apache Log4j2 JNDI injection",
        "target": target,
        "port": 443,
        "severity": "CRITICAL",
        "cve_id": "CVE-2021-44228",
        "is_cisa_kev": True,
        "confidence": "HIGH",
        "evidence": "Product matched nvd CPE on 10.20.0.14:443",
        "timestamp": "2026-10-30T20:00:00+00:00",
    }


def _high_unverified(target="10.20.0.14"):
    return {
        "id": "AEGIS-TLS-001",
        "title": "TLS 1.0 offered",
        "target": target,
        "port": 443,
        "severity": "HIGH",
        "cve_id": None,
        "is_cisa_kev": False,
        "confidence": "MEDIUM",
        "evidence": "Server hello included TLS 1.0",
        "timestamp": "2026-10-30T20:00:00+00:00",
    }


def _detect(src="10.20.0.14", dest="198.51.100.9", ts="2026-10-30T21:00:00+00:00"):
    monitor.alerts = [{
        "id": "ALT-LOOP-1",
        "pattern_id": "AEGIS-BEH-002",
        "severity": "HIGH",
        "title": "C2 beacon",
        "source_ip": src,
        "dest_ip": dest,
        "dest_port": 443,
        "process": "svc.exe",
        "tactic": "Command and Control",
        "technique": "T1071",
        "evidence": f"{src} → {dest}:443 regular interval",
        "timestamp": ts,
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


def _incidents(client):
    res = client.get("/api/monitor", headers=_auth())
    assert res.status_code == 200, res.text
    return res.json()["incidents"]


def test_verified_high_kev_predicate():
    assert is_verified_high_kev(_kev_finding())
    assert not is_verified_high_kev(_high_unverified())
    assert not is_verified_high_kev({"id": "X", "severity": "HIGH", "confidence": "HIGH", "evidence": ""})
    live = dict(_high_unverified())
    live["verification"] = {"status": "VULNERABLE", "is_vulnerable": True}
    assert is_verified_high_kev(live)


def test_empty_site_has_no_loop_incident(client):
    assert _incidents(client) == []
    catalog = client.get("/api/assets", headers=_auth()).json()
    assert catalog["assets"] == []


def test_finding_without_detect_does_not_invent_an_incident(client):
    _enroll_heartbeat(client)
    _scan("SCANKEV", "10.20.0.14", [_kev_finding()])
    assert _incidents(client) == []
    posture = client.get("/api/assets", headers=_auth()).json()["assets"][0]["posture"]
    assert posture["kev_count"] == 1
    assert posture["findings"][0]["verified"] is True


def test_detect_without_enrolled_host_has_no_closed_loop(client):
    _detect(src="203.0.113.50")
    inc = _incidents(client)[0]
    assert inc["loop"]["closed"] is False
    assert inc["loop"]["empty_reason"] == EMPTY_NO_HOST
    assert "Isolate host" not in str(inc.get("executable_actions"))


def test_detect_without_verified_finding_has_no_closed_loop(client):
    _enroll_heartbeat(client)
    _scan("SCANHIGH", "10.20.0.14", [_high_unverified()])
    _detect()
    inc = _incidents(client)[0]
    assert inc["loop"]["closed"] is False
    assert inc["loop"]["empty_reason"] == EMPTY_NO_FINDING
    assert inc["alerts"]


def test_unmatched_scan_does_not_close_loop_for_another_host(client):
    _enroll_heartbeat(client, ipv4="10.20.0.14")
    _scan("SCANOTHER", "198.51.100.40", [_kev_finding("198.51.100.40")])
    _detect()
    inc = _incidents(client)[0]
    assert inc["loop"]["closed"] is False
    assert inc["loop"]["empty_reason"] == EMPTY_NO_FINDING


def test_detect_before_finding_does_not_close(client):
    _enroll_heartbeat(client)
    _scan(
        "SCANLATE",
        "10.20.0.14",
        [_kev_finding()],
        started_at="2026-10-30T22:00:00+00:00",
    )
    scans["SCANLATE"]["findings"][0]["timestamp"] = "2026-10-30T22:00:00+00:00"
    _detect(ts="2026-10-30T21:00:00+00:00")
    inc = _incidents(client)[0]
    assert inc["loop"]["closed"] is False


def test_golden_path_one_incident_with_finding_ids_and_samples(client):
    payload = _enroll_heartbeat(client)
    _scan("SCANKEV", "10.20.0.14", [_kev_finding(), _high_unverified()])
    _detect()
    incidents = _incidents(client)
    assert len(incidents) == 1
    inc = incidents[0]
    loop = inc["loop"]
    assert loop["closed"] is True
    assert loop["empty_reason"] is None
    assert loop["host"]["agent_id"] == payload["agent_id"]
    finding_ids = [row["finding_id"] for row in loop["prevent"]["findings"]]
    assert finding_ids == ["CVE-2021-44228"]
    assert "AEGIS-TLS-001" not in finding_ids
    assert loop["detect"]["pattern_ids"] == ["AEGIS-BEH-002"]
    assert loop["detect"]["alerts"][0]["id"] == "ALT-LOOP-1"
    sample = loop["prevent"]["findings"][0]
    assert sample["kind"] == "finding"
    assert sample["id"] == "SCANKEV:CVE-2021-44228"
    assert sample["evidence"]
    detect = loop["detect"]["alerts"][0]
    assert detect["kind"] == "alert"
    assert detect["id"] == "ALT-LOOP-1"
    claims = inc["analyst_assist"]["claims"]
    claim_ids = {c["sample_id"] for c in claims}
    assert "SCANKEV:CVE-2021-44228" in claim_ids
    assert "ALT-LOOP-1" in claim_ids
    for claim in claims:
        assert claim["sample"]["id"] == claim["sample_id"]
    assert inc["analyst_assist"]["evidence_linked"] is True
    assert any(a["action"] == "quarantine_host" for a in inc["executable_actions"])
    proposals = inc["response"]["proposals"]
    assert any(p["rule_id"] == "AEGIS-RSP-005" and p["action"] == "quarantine_host" for p in proposals)
    inv = client.get(f"/api/investigations?host={payload['agent_id']}", headers=_auth()).json()
    assert inv["loop"]["closed"] is True
    assert inv["loop"]["prevent"]["findings"][0]["finding_id"] == "CVE-2021-44228"


def test_recommend_isolate_confirm_signs_audit(client):
    payload = _enroll_heartbeat(client)
    _scan("SCANKEV", "10.20.0.14", [_kev_finding()])
    _detect()
    inc = _incidents(client)[0]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "quarantine_host", "target": payload["agent_id"]},
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["mode"] == "recommend"
    assert body["status"] == "preview"
    assert body["rule_id"] == "AEGIS-RSP-005"
    assert "CVE-2021-44228" in ((body.get("evidence") or {}).get("finding_ids") or [])
    assert "ALT-LOOP-1" in ((body.get("evidence") or {}).get("alert_ids") or [])
    assert verify_audit(body["audit"])
    confirmed = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": body["action_id"], "confirm": True},
    )
    assert confirmed.status_code == 200, confirmed.text
    done = confirmed.json()
    assert done["status"] == "queued"
    assert done["confirmed"] is True
    assert verify_audit(done["audit"])
    audit = client.get(f"/api/response/actions/{done['action_id']}/audit", headers=_auth()).json()
    assert audit["verified"] is True
    assert "CVE-2021-44228" in (audit["audit"]["payload"].get("evidence_finding_ids") or [])
    assert client.fake.quarantined == set()


def test_confirm_pages_slack_under_hourly_cap(client, monkeypatch):
    from aegis.alerting.models import ChannelType, DispatchResult

    payload = _enroll_heartbeat(client)
    _scan("SCANKEV", "10.20.0.14", [_kev_finding()])
    _detect()
    alert_router.platforms.save("slack", "", {
        "account_label": "Acme",
        "destination_label": "#soc",
        "secret": "https://hooks.slack.com/services/T/B/super-secret-hook",
        "secret_kind": "webhook",
    })
    alert_router.cap.set_hourly_cap(10)
    sent = []

    async def fake_deliver(connection, text, client=None):
        sent.append({"provider": connection["provider"], "text": text})
        assert "super-secret-hook" not in text
        assert "CVE-2021-44228" in text
        assert "AEGIS-BEH-002" in text
        return DispatchResult(channel=ChannelType.WEBHOOK, success=True, recipient="#soc")

    monkeypatch.setattr("aegis.alerting.router.deliver", fake_deliver)
    inc = _incidents(client)[0]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "quarantine_host", "target": payload["agent_id"]},
    ).json()
    done = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": preview["action_id"], "confirm": True},
    ).json()
    assert done["paging"]["status"] == "page"
    assert done["paging"]["provider"] == "slack"
    assert sent and sent[0]["provider"] == "slack"
    picture = alert_router.cap.snapshot()
    assert picture["sent_this_hour"] == 1
    assert picture["hourly_cap"] == 10


def test_hourly_cap_holds_loop_page(client, monkeypatch):
    from aegis.alerting.models import ChannelType, DispatchResult

    payload = _enroll_heartbeat(client)
    _scan("SCANKEV", "10.20.0.14", [_kev_finding()])
    _detect()
    alert_router.platforms.save("slack", "", {
        "account_label": "Acme",
        "destination_label": "#soc",
        "secret": "https://hooks.slack.com/services/T/B/hook",
        "secret_kind": "webhook",
    })
    alert_router.cap.set_hourly_cap(1)
    alert_router.cap.reserve()
    sent = []

    async def fake_deliver(connection, text, client=None):
        sent.append(text)
        return DispatchResult(channel=ChannelType.WEBHOOK, success=True, recipient="#soc")

    monkeypatch.setattr("aegis.alerting.router.deliver", fake_deliver)
    inc = _incidents(client)[0]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "quarantine_host", "target": payload["agent_id"]},
    ).json()
    done = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": preview["action_id"], "confirm": True},
    ).json()
    assert done["paging"]["status"] in {"summary", "hold"}
    assert done["paging"]["hourly_cap"] == 1


def test_no_destination_does_not_invent_a_page(client):
    payload = _enroll_heartbeat(client)
    _scan("SCANKEV", "10.20.0.14", [_kev_finding()])
    _detect()
    alert_router.platforms.disconnect("slack", "")
    inc = _incidents(client)[0]
    preview = client.post(
        "/api/response/preview",
        headers=_auth(),
        json={"incident_id": inc["id"], "action": "quarantine_host", "target": payload["agent_id"]},
    ).json()
    done = client.post(
        "/api/response/confirm",
        headers=_auth(),
        json={"action_id": preview["action_id"], "confirm": True},
    ).json()
    assert done["paging"]["status"] == "no_destination"
    assert verify_audit(done["audit"])


def test_live_retest_can_verify_a_high_finding(client):
    _enroll_heartbeat(client)
    finding = _high_unverified()
    _scan("SCANHIGH", "10.20.0.14", [finding])
    _detect()
    assert _incidents(client)[0]["loop"]["closed"] is False
    scans["SCANHIGH"]["findings"][0]["verification"] = {
        "status": "VULNERABLE",
        "is_vulnerable": True,
        "timestamp": "2026-10-30T20:30:00+00:00",
        "summary": "TLS 1.0 still offered",
    }
    inc = _incidents(client)[0]
    assert inc["loop"]["closed"] is True
    assert inc["loop"]["prevent"]["findings"][0]["finding_id"] == "AEGIS-TLS-001"


def test_ui_loop_copy_and_no_darktrace_chrome():
    index = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    incident_js = (ROOT / "static" / "incident.js").read_text(encoding="utf-8")
    investigate_js = (ROOT / "static" / "investigate.js").read_text(encoding="utf-8")
    loop_py = (ROOT / "aegis" / "monitor" / "closed_loop.py").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for blob in (incident_js, investigate_js, loop_py):
        assert "Antigena" not in blob
        assert "Inoculation" not in blob
        assert "Patterns of Life" not in blob
        assert "Threat Visualizer" not in blob
        assert "--dt-magenta" not in blob
    assert "Prevent → Detect" in incident_js
    assert "loop-rail" in index
    assert "Isolate host" in index
    assert 'id="routing-status"' in index
    dash = index[index.index("Alert routing status"):index.index("page-scan")]
    assert "Tap Connect" not in dash
    assert "Settings →" in dash
    assert "function paintRoutingStatus" in index
    assert "hourly cap" in readme.lower()
    assert EMPTY_NO_DETECT
    assert EMPTY_NO_FINDING
    assert EMPTY_NO_HOST
