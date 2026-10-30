"""Well-known web edges are not scored as C2. Other beacons still are."""

import time

from aegis.monitor.network_monitor import NetworkMonitor
from aegis.monitor.threat_patterns import is_routine_web_edge_traffic, is_well_known_web_edge


def _seed(mon, src, dst, port, now):
    mon.conn_history[(src, dst, port)] = [now - 90, now - 60, now - 30, now]


def test_google_address_is_a_web_edge():
    assert is_well_known_web_edge("172.217.113.4")
    assert is_well_known_web_edge("192.178.155.132")
    assert is_routine_web_edge_traffic("172.217.113.4", 443)
    assert not is_routine_web_edge_traffic("172.217.113.4", 4444)
    from aegis.monitor.threat_patterns import is_routine_web_edge_beacon
    assert is_routine_web_edge_beacon({
        "pattern_id": "AEGIS-BEH-002",
        "dest_ip": "172.217.113.4",
        "dest_port": 443,
    })
    assert not is_routine_web_edge_beacon({
        "pattern_id": "AEGIS-BEH-002",
        "dest_ip": "45.33.32.156",
        "dest_port": 443,
    })


def test_google_https_is_not_a_c2_beacon():
    mon = NetworkMonitor()
    now = time.time()
    src, dst = "10.103.198.27", "172.217.113.4"
    _seed(mon, src, dst, 443, now)
    mon._check_beaconing(src, {dst}, now)
    assert mon.alerts == []


def test_non_google_beacon_still_alerts():
    mon = NetworkMonitor()
    now = time.time()
    src, dst = "10.103.198.27", "45.33.32.156"
    _seed(mon, src, dst, 443, now)
    mon._check_beaconing(src, {dst}, now)
    assert len(mon.alerts) == 1
    assert mon.alerts[0]["pattern_id"] == "AEGIS-BEH-002"
    assert mon.alerts[0]["dest_ip"] == dst
    assert mon.alerts[0]["severity"] == "CRITICAL"


def test_cdn_and_microsoft_365_https_is_not_a_c2_beacon():
    assert is_well_known_web_edge("108.156.221.54")
    assert is_well_known_web_edge("2.21.98.40")
    assert is_well_known_web_edge("52.98.22.2")
    mon = NetworkMonitor()
    now = time.time()
    src = "10.103.198.27"
    for dst in ("108.156.221.54", "2.21.98.40", "52.98.22.2"):
        _seed(mon, src, dst, 443, now)
        mon._check_beaconing(src, {dst}, now)
    assert mon.alerts == []


def test_browser_fanout_is_not_a_c2_beacon():
    mon = NetworkMonitor()
    now = time.time()
    src = "10.103.198.27"
    dests = ["45.33.32.10", "45.33.32.11", "45.33.32.12", "45.33.32.13"]
    for dst in dests:
        _seed(mon, src, dst, 443, now)
    mon._check_beaconing(src, set(dests), now)
    assert mon.alerts == []
    _seed(mon, src, "45.33.32.10", 4444, now)
    mon._check_beaconing(src, {"45.33.32.10"}, now)
    assert len(mon.alerts) == 1
    assert mon.alerts[0]["dest_port"] == 4444


def test_queued_fanout_beacons_are_hidden():
    from aegis.monitor.threat_patterns import hidden_queued_beacon_ids
    rows = []
    for idx, dest in enumerate(("45.33.32.10", "45.33.32.11", "45.33.32.12", "45.33.32.13")):
        rows.append({
            "alert_id": f"CALT-{idx}",
            "title": f"C2 Beaconing Detected: 10.1.1.1 → {dest}",
            "source_ip": "10.1.1.1",
            "dest_ip": dest,
            "dest_port": 443,
            "metadata": {"raw_pattern_id": "AEGIS-BEH-002"},
        })
    rows.append({
        "alert_id": "CALT-REAL",
        "title": "C2 Beaconing Detected: 10.1.1.8 → 203.0.113.9",
        "source_ip": "10.1.1.8",
        "dest_ip": "203.0.113.9",
        "dest_port": 4444,
        "metadata": {"raw_pattern_id": "AEGIS-BEH-002"},
    })
    hidden = hidden_queued_beacon_ids(rows)
    assert hidden == {"CALT-0", "CALT-1", "CALT-2", "CALT-3"}


def test_google_non_web_port_still_alerts():
    mon = NetworkMonitor()
    now = time.time()
    src, dst = "10.103.198.27", "172.217.113.4"
    _seed(mon, src, dst, 4444, now)
    mon._check_beaconing(src, {dst}, now)
    assert len(mon.alerts) == 1
    assert mon.alerts[0]["dest_port"] == 4444
