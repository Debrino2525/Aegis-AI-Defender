"""Analyst Assist: host+time+tactic groups, evidence-linked phases/hops, no fakes."""

import os
from collections import defaultdict
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.investigate.device import DeviceSources, build_investigation
from aegis.monitor.ai_analyst import AIAnalyst
from aegis.monitor.analyst_assist import PRODUCT_NAME, build_analyst_assist
from aegis.monitor.network_monitor import NetworkMonitor
from aegis.fleet.service import reset_fleet_service
from server import analyst, app, monitor, scans

ROOT = Path(__file__).resolve().parents[1]


def _alert(alert_id, src, tactic, pattern, dest="198.51.100.9", port=443, ts=10.0, title=None, **extra):
    row = {
        "id": alert_id,
        "pattern_id": pattern,
        "severity": extra.pop("severity", "HIGH"),
        "title": title or f"{pattern} on {src}",
        "source_ip": src,
        "dest_ip": dest,
        "dest_port": port,
        "process": extra.pop("process", "svc.exe"),
        "evidence": extra.pop("evidence", f"{src} → {dest}:{port}"),
        "tactic": tactic,
        "technique": extra.pop("technique", "T1071"),
        "timestamp": "2026-10-30T21:00:00+00:00",
        "_timestamp": ts,
        "acknowledged": False,
    }
    row.update(extra)
    return row


def _sock(src, dst, port, process="svc.exe"):
    return {
        "local_ip": src,
        "remote_ip": dst,
        "remote_port": port,
        "status": "ESTABLISHED",
        "pid": 9,
        "process": process,
        "timestamp": "2026-10-30T21:00:00+00:00",
    }


def _assert_claims_linked(assist):
    assert assist["product"] == PRODUCT_NAME
    assert assist["evidence_linked"] is True
    for claim in assist["claims"]:
        assert claim["sample_id"]
        assert claim["sample"]
        assert claim["sample"]["id"] == claim["sample_id"]


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


def _auth():
    return {"Authorization": f"Bearer {os.environ['AEGIS_ADMIN_TOKEN']}"}


def test_groups_by_host_time_tactic_not_beh_titles():
    src = "10.20.0.14"
    alerts = [
        _alert("ALT-1", src, "Command and Control", "AEGIS-BEH-002", ts=1),
        _alert("ALT-2", src, "Command and Control", "AEGIS-BEH-002", dest="198.51.100.10", ts=2),
        _alert("ALT-3", src, "Lateral Movement", "AEGIS-BEH-010", dest="10.20.0.20", port=445, ts=3),
    ]
    engine = AIAnalyst()
    incidents = engine.analyze(alerts)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["product"] == "Analyst Assist"
    tactics = [g["tactic"] for g in inc["groups"]]
    assert tactics == ["Command and Control", "Lateral Movement"] or set(tactics) == {
        "Command and Control",
        "Lateral Movement",
    }
    assert len(inc["groups"]) == 2
    c2 = next(g for g in inc["groups"] if g["tactic"] == "Command and Control")
    assert c2["host"] == src
    assert set(c2["alert_ids"]) == {"ALT-1", "ALT-2"}
    assert c2["pattern_ids"] == ["AEGIS-BEH-002"]
    _assert_claims_linked(inc["analyst_assist"])


def test_time_window_splits_incidents():
    src = "10.20.0.14"
    engine = AIAnalyst()
    incidents = engine.analyze([
        _alert("ALT-1", src, "Command and Control", "AEGIS-BEH-002", ts=1),
        _alert("ALT-2", src, "Command and Control", "AEGIS-BEH-002", ts=1 + AIAnalyst.CORRELATION_WINDOW + 1),
    ])
    assert len(incidents) == 2
    ids = {inc["id"] for inc in incidents}
    assert ids == {"INC-0001", "INC-0002"}


def test_two_hosts_are_two_incidents():
    engine = AIAnalyst()
    incidents = engine.analyze([
        _alert("ALT-1", "10.0.0.1", "Command and Control", "AEGIS-BEH-002"),
        _alert("ALT-2", "10.0.0.2", "Lateral Movement", "AEGIS-BEH-010", dest="10.0.0.3", port=445),
    ])
    assert len(incidents) == 2


def test_phases_only_when_two_plus_have_evidence():
    src = "10.20.0.14"
    c2_only = build_analyst_assist([
        _alert("ALT-1", src, "Command and Control", "AEGIS-BEH-002"),
    ])
    assert c2_only["phases"] == []
    assert any("Multi-phase" in gap for gap in c2_only["gaps"])

    multi = build_analyst_assist([
        _alert("ALT-1", src, "Initial Access", "AEGIS-BEH-001", port=0, dest="multiple"),
        _alert("ALT-2", src, "Lateral Movement", "AEGIS-BEH-010", dest="10.20.0.20", port=445),
        _alert("ALT-3", src, "Impact", "AEGIS-BEH-003", dest="198.51.100.9", port=443),
    ])
    assert [p["phase"] for p in multi["phases"]] == ["initial", "lateral", "impact"]
    for phase in multi["phases"]:
        assert phase["evidence"]
        assert phase["alert_ids"]
    _assert_claims_linked(multi)


def test_no_fake_hops_from_smb_alert_or_star():
    src = "10.20.0.14"
    alerts = [
        _alert(
            "ALT-smb",
            src,
            "Lateral Movement",
            "AEGIS-BEH-010",
            dest="multiple internal",
            port=445,
            evidence="SMB (port 445) connections to 3 unique hosts",
        )
    ]
    star = [
        _sock(src, "10.20.0.21", 445),
        _sock(src, "10.20.0.22", 445),
        _sock(src, "10.20.0.23", 445),
    ]
    assist = build_analyst_assist(alerts, connections=star)
    assert assist["hops"] == []
    assert any("No hop path" in gap for gap in assist["gaps"])
    for claim in assist["claims"]:
        assert "10.20.0.21 → 10.20.0.22" not in claim["text"]


def test_hop_path_only_when_a_to_b_to_c_observed():
    src = "10.20.0.14"
    mid = "10.20.0.20"
    dst = "10.20.0.30"
    alerts = [_alert("ALT-1", src, "Lateral Movement", "AEGIS-BEH-010", dest=mid, port=3389)]
    assist = build_analyst_assist(
        alerts,
        connections=[
            _sock(src, mid, 3389, "rdpclip.exe"),
            _sock(mid, dst, 445, "smb.exe"),
        ],
    )
    assert len(assist["hops"]) == 1
    hop = assist["hops"][0]
    assert hop["path"] == [src, mid, dst]
    assert hop["edges"][0]["protocol"] == "RDP"
    assert hop["edges"][0]["port"] == 3389
    assert hop["edges"][1]["protocol"] == "SMB"
    assert hop["edges"][1]["port"] == 445
    assert hop["edges"][0]["sample_id"]
    assert hop["edges"][1]["sample"]["kind"] == "hop" or hop["edges"][1]["sample"]["id"]
    _assert_claims_linked(assist)


def test_agent_hop_connections_can_complete_a_path():
    src = "10.20.0.14"
    mid = "10.20.0.20"
    dst = "10.20.0.30"
    assist = build_analyst_assist(
        [_alert(
            "ALT-1",
            src,
            "Lateral Movement",
            "AEGIS-BEH-010",
            dest="multiple internal",
            port=445,
        )],
        hosts=[
            {
                "agent_id": "agt_a",
                "hop_connections": [{"local_ip": src, "remote_ip": mid, "remote_port": 3389}],
            },
            {
                "agent_id": "agt_b",
                "hop_connections": [{"local_ip": mid, "remote_ip": dst, "remote_port": 445}],
            },
        ],
        focus_hosts=[src],
    )
    assert assist["hops"][0]["path"] == [src, mid, dst]
    seen_by = {edge["seen_by"] for edge in assist["hops"][0]["edges"]}
    assert seen_by == {"agent"}


def test_related_detections_are_pattern_ids_on_the_host():
    src = "10.20.0.14"
    assist = build_analyst_assist([
        _alert("ALT-1", src, "Command and Control", "AEGIS-BEH-002"),
        _alert("ALT-2", src, "Lateral Movement", "AEGIS-BEH-010", dest="10.20.0.20", port=445),
        _alert("ALT-3", src, "Lateral Movement", "AEGIS-BEH-010", dest="10.20.0.21", port=445),
    ])
    ids = {row["pattern_id"] for row in assist["related_detections"]}
    assert ids == {"AEGIS-BEH-002", "AEGIS-BEH-010"}
    smb = next(row for row in assist["related_detections"] if row["pattern_id"] == "AEGIS-BEH-010")
    assert set(smb["alert_ids"]) == {"ALT-2", "ALT-3"}
    assert smb["sample_id"]


def test_https_is_not_a_hop():
    assist = build_analyst_assist(
        [_alert("ALT-1", "10.20.0.14", "Command and Control", "AEGIS-BEH-002")],
        connections=[
            _sock("10.20.0.14", "10.20.0.20", 443),
            _sock("10.20.0.20", "10.20.0.30", 443),
        ],
    )
    assert assist["hops"] == []


def test_investigation_includes_analyst_assist_and_hops():
    src = "203.0.113.50"
    mid = "203.0.113.51"
    dst = "203.0.113.52"
    sources = DeviceSources(
        connections=[
            _sock(src, mid, 22, "ssh"),
            _sock(mid, dst, 445, "smb"),
        ],
        monitor_alerts=[
            _alert("ALT-0401", src, "Lateral Movement", "AEGIS-BEH-010", dest=mid, port=22),
        ],
    )
    body = build_investigation(sources, f"ip:{src}")
    assert body["product"] == "Analyst Assist"
    assist = body["analyst_assist"]
    assert assist["groups"]
    assert assist["hops"][0]["path"] == [src, mid, dst]
    _assert_claims_linked(assist)
    unrelated = build_investigation(sources, "ip:198.51.100.200")
    assert unrelated["analyst_assist"]["hops"] == []


def test_monitor_api_returns_analyst_assist(client):
    src = "203.0.113.60"
    mid = "203.0.113.61"
    dst = "203.0.113.62"
    monitor.alerts = [
        _alert("ALT-0501", src, "Initial Access", "AEGIS-BEH-001", dest="multiple", port=0),
        _alert("ALT-0502", src, "Lateral Movement", "AEGIS-BEH-010", dest=mid, port=3389),
    ]
    monitor.current_connections = [
        _sock(src, mid, 3389),
        _sock(mid, dst, 445),
    ]
    res = client.get("/api/monitor", headers=_auth())
    assert res.status_code == 200
    incidents = res.json()["incidents"]
    assert incidents
    inc = incidents[0]
    assert inc["product"] == "Analyst Assist"
    assert inc["analyst_assist"]["product"] == "Analyst Assist"
    assert len(inc["groups"]) == 2
    assert [p["phase"] for p in inc["phases"]] == ["initial", "lateral"]
    assert inc["hops"][0]["path"] == [src, mid, dst]
    assert inc["related_detections"]
    _assert_claims_linked(inc["analyst_assist"])
    assert "APT" not in (inc["narrative"] or "")
    assert "Analyst Assist" in inc["narrative"]


def test_pages_say_analyst_assist_not_darktrace(client):
    incident_js = client.get("/static/incident.js").text
    investigate_js = client.get("/static/investigate.js").text
    index_html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    incident_css = (ROOT / "static" / "incident.css").read_text(encoding="utf-8")
    for blob in (incident_js, investigate_js, index_html):
        assert "Analyst Assist" in blob
        assert "Antigena" not in blob
        assert "Patterns of Life" not in blob
        assert "Inoculation" not in blob
        assert "--dt-magenta" not in blob
        assert "world_map.svg" not in incident_js
        assert "world_map.svg" not in investigate_js
    assert "AI Analyst" not in incident_js
    assert "AI Analyst" not in investigate_js
    assert "AI Analyst" not in index_html
    assert "hop-path" in incident_css
    assert "phase-list" in incident_css
    assert "Threat Visualizer" not in incident_js
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Analyst Assist" in readme
    assert "AI Analyst Incident Correlation" not in readme
