"""
Regression tests for monitor alert identity and incident correlation.

Opening the live monitor must not erase the dedup metadata that suppresses
repeat pages, and a resolved incident must not absorb a later attack from
the same host.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.monitor.ai_analyst import AIAnalyst
from aegis.monitor.network_monitor import NetworkMonitor


def _alert(alert_id, src, ts, pattern="AEGIS-BEH-002", severity="CRITICAL", title="C2 Beaconing"):
    return {
        "id": alert_id,
        "pattern_id": pattern,
        "severity": severity,
        "title": title,
        "description": "test",
        "source_ip": src,
        "dest_ip": "203.0.113.10",
        "dest_port": 443,
        "process": "",
        "evidence": "interval",
        "tactic": "Command and Control",
        "technique": "T1071",
        "timestamp": "2026-11-09T11:00:00",
        "acknowledged": False,
        "_timestamp": ts,
        "_dedup_key": f"{pattern}:{src}:203.0.113.10",
    }


def test_get_state_preserves_dedup_metadata():
    mon = NetworkMonitor()
    now = time.time()
    mon.alerts.append(_alert("ALT-0001", "10.0.0.8", now))

    state = mon.get_state()
    assert state["alerts"], "dashboard snapshot should include the alert"
    assert "_dedup_key" not in state["alerts"][0]
    assert "_timestamp" not in state["alerts"][0]
    assert state["alerts"][0] is not mon.alerts[0]

    # What the websocket used to do to the objects get_state returned.
    for alert in state["alerts"]:
        alert.pop("_timestamp", None)
        alert.pop("_dedup_key", None)

    assert mon.alerts[0]["_dedup_key"] == "AEGIS-BEH-002:10.0.0.8:203.0.113.10"
    assert mon.alerts[0]["_timestamp"] == now

    mon._emit_alert(
        pattern_id="AEGIS-BEH-002",
        severity="CRITICAL",
        title="C2 Beaconing",
        description="still going",
        source_ip="10.0.0.8",
        dest_ip="203.0.113.10",
        dest_port=443,
        process="",
        evidence="interval",
        tactic="Command and Control",
        technique="T1071",
    )
    assert len(mon.alerts) == 1, "ongoing condition must stay suppressed for 5 minutes"
    print("[+] test_get_state_preserves_dedup_metadata: PASSED")


def test_resolved_incident_does_not_swallow_new_attack():
    analyst = AIAnalyst()
    now = time.time()
    src = "10.0.0.8"
    first = analyst.analyze([_alert("ALT-0001", src, now, pattern="AEGIS-BEH-001", title="Port Scan", severity="HIGH")])
    assert len(first) == 1
    assert first[0]["status"] == "ACTIVE"
    analyst.get_incident(first[0]["id"]).status = "RESOLVED"

    later = analyst.analyze([
        _alert("ALT-0001", src, now, pattern="AEGIS-BEH-001", title="Port Scan", severity="HIGH"),
        _alert("ALT-0002", src, now + 30, title="C2 Beaconing"),
    ])
    by_id = {inc["id"]: inc for inc in later}
    assert by_id[first[0]["id"]]["status"] == "RESOLVED"
    assert by_id[first[0]["id"]]["alert_count"] == 1
    active = [inc for inc in later if inc["status"] == "ACTIVE"]
    assert len(active) == 1
    assert active[0]["alert_count"] == 1
    assert active[0]["alert_ids"] == ["ALT-0002"]
    print("[+] test_resolved_incident_does_not_swallow_new_attack: PASSED")


def test_correlation_window_splits_and_replay_does_not_duplicate():
    analyst = AIAnalyst()
    now = time.time()
    src = "10.1.1.5"
    analyst.analyze([_alert("ALT-0100", src, now, title="Port Scan", pattern="AEGIS-BEH-001", severity="HIGH")])
    attached = analyst.analyze([
        _alert("ALT-0100", src, now, title="Port Scan", pattern="AEGIS-BEH-001", severity="HIGH"),
        _alert("ALT-0101", src, now + 60, title="C2 Beaconing"),
    ])
    assert len(attached) == 1
    assert attached[0]["alert_count"] == 2

    split = analyst.analyze([
        _alert("ALT-0100", src, now, title="Port Scan", pattern="AEGIS-BEH-001", severity="HIGH"),
        _alert("ALT-0101", src, now + 60, title="C2 Beaconing"),
        _alert("ALT-0102", src, now + 60 + AIAnalyst.CORRELATION_WINDOW + 30, title="Exfil", pattern="AEGIS-BEH-003", severity="CRITICAL"),
    ])
    assert len(split) == 2
    counts = sorted(inc["alert_count"] for inc in split)
    assert counts == [1, 2]

    replay = analyst.analyze([
        _alert("ALT-0100", src, now, title="Port Scan", pattern="AEGIS-BEH-001", severity="HIGH"),
        _alert("ALT-0101", src, now + 60, title="C2 Beaconing"),
        _alert("ALT-0102", src, now + 60 + AIAnalyst.CORRELATION_WINDOW + 30, title="Exfil", pattern="AEGIS-BEH-003", severity="CRITICAL"),
    ])
    assert sorted(inc["alert_count"] for inc in replay) == [1, 2]
    print("[+] test_correlation_window_splits_and_replay_does_not_duplicate: PASSED")


def test_contained_incident_reopens_when_activity_continues():
    analyst = AIAnalyst()
    now = time.time()
    src = "10.2.2.9"
    first = analyst.analyze([_alert("ALT-0200", src, now)])
    incident = analyst.get_incident(first[0]["id"])
    incident.status = "CONTAINED"

    reopened = analyst.analyze([
        _alert("ALT-0200", src, now),
        _alert("ALT-0201", src, now + 45),
    ])
    assert len(reopened) == 1
    assert reopened[0]["status"] == "ACTIVE"
    assert reopened[0]["alert_count"] == 2
    print("[+] test_contained_incident_reopens_when_activity_continues: PASSED")


if __name__ == "__main__":
    test_get_state_preserves_dedup_metadata()
    test_resolved_incident_does_not_swallow_new_attack()
    test_correlation_window_splits_and_replay_does_not_duplicate()
    test_contained_incident_reopens_when_activity_continues()
    print("\n[=== MONITOR INCIDENT TESTS PASSED ===]")
