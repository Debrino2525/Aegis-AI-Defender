"""Well-known web edges are not scored as C2. Other beacons still are."""

import time

from aegis.monitor.network_monitor import NetworkMonitor
from aegis.monitor.threat_patterns import is_routine_web_edge_traffic, is_well_known_web_edge


def _seed(mon, src, dst, port, now):
    mon.conn_history[(src, dst, port)] = [now - 90, now - 60, now - 30, now]


def test_google_address_is_a_web_edge():
    assert is_well_known_web_edge("172.217.113.4")
    assert is_routine_web_edge_traffic("172.217.113.4", 443)
    assert not is_routine_web_edge_traffic("172.217.113.4", 4444)


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


def test_google_non_web_port_still_alerts():
    mon = NetworkMonitor()
    now = time.time()
    src, dst = "10.103.198.27", "172.217.113.4"
    _seed(mon, src, dst, 4444, now)
    mon._check_beaconing(src, {dst}, now)
    assert len(mon.alerts) == 1
    assert mon.alerts[0]["dest_port"] == 4444
