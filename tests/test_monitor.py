"""Detection tests for the live network monitor.

A long-lived socket must not be reported as C2 beaconing just because the
sampler observes it on every tick, and several SMB sessions to one file
server must not be reported as lateral movement.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.monitor import network_monitor as nm
from aegis.monitor.network_monitor import NetworkMonitor


class _Addr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _Conn:
    def __init__(self, local_ip, remote_ip, remote_port):
        self.laddr = _Addr(local_ip, 40000)
        self.raddr = _Addr(remote_ip, remote_port)
        self.status = "ESTABLISHED"
        self.pid = None


def _patterns(monitor, pattern_id):
    return [a for a in monitor.alerts if a["pattern_id"] == pattern_id]


async def _sample(monitor, conns, now):
    with patch.object(nm.time, "time", lambda: now), patch.object(
        nm.psutil, "net_connections", lambda kind="inet": conns
    ):
        await monitor._sample_connections()


def test_persistent_connection_is_not_c2_beaconing():
    """A browser tab that stays open is sampled every ~5s and must not page on-call."""
    monitor = NetworkMonitor()
    conn = _Conn("10.0.0.8", "93.184.216.34", 443)
    now = 1_700_000_000.0

    async def run():
        for i in range(8):
            await _sample(monitor, [conn], now + (i * 5.2))

    asyncio.run(run())
    assert _patterns(monitor, "AEGIS-BEH-002") == []
    print("[+] test_persistent_connection_is_not_c2_beaconing: PASSED")


def test_reconnect_interval_is_c2_beaconing():
    """A socket that drops and returns on a steady interval is a beacon."""
    monitor = NetworkMonitor()
    conn = _Conn("10.0.0.8", "185.220.101.5", 443)
    start = 1_700_000_000.0

    async def run():
        for i in range(4):
            await _sample(monitor, [conn], start + (i * 30))
            await _sample(monitor, [], start + (i * 30) + 5)

    asyncio.run(run())
    hits = _patterns(monitor, "AEGIS-BEH-002")
    assert len(hits) == 1
    assert "185.220.101.5" in hits[0]["title"]
    print("[+] test_reconnect_interval_is_c2_beaconing: PASSED")


def test_smb_sessions_to_one_host_are_not_lateral_movement():
    """Three TCP sessions to a single file server are normal, not worm propagation."""
    monitor = NetworkMonitor()
    conns = [_Conn("10.0.0.8", "10.0.0.5", 445) for _ in range(3)]

    asyncio.run(_sample(monitor, conns, 1_700_000_000.0))
    assert _patterns(monitor, "AEGIS-BEH-010") == []
    print("[+] test_smb_sessions_to_one_host_are_not_lateral_movement: PASSED")


def test_smb_to_many_internal_hosts_is_lateral_movement():
    monitor = NetworkMonitor()
    conns = [
        _Conn("10.0.0.8", "10.0.0.5", 445),
        _Conn("10.0.0.8", "10.0.0.6", 445),
        _Conn("10.0.0.8", "10.0.0.7", 445),
    ]

    asyncio.run(_sample(monitor, conns, 1_700_000_000.0))
    hits = _patterns(monitor, "AEGIS-BEH-010")
    assert len(hits) == 1
    assert "3 unique internal hosts" in hits[0]["evidence"]
    print("[+] test_smb_to_many_internal_hosts_is_lateral_movement: PASSED")


def test_external_smb_is_not_lateral_movement():
    monitor = NetworkMonitor()
    conns = [
        _Conn("10.0.0.8", "8.8.8.8", 445),
        _Conn("10.0.0.8", "1.1.1.1", 445),
        _Conn("10.0.0.8", "9.9.9.9", 445),
    ]

    asyncio.run(_sample(monitor, conns, 1_700_000_000.0))
    assert _patterns(monitor, "AEGIS-BEH-010") == []
    print("[+] test_external_smb_is_not_lateral_movement: PASSED")


def test_alert_ids_stay_unique_after_the_history_cap():
    """The visible history keeps 500 alerts, but ids must not restart at ALT-0501.

    Acknowledgement looks alerts up by id. Reused ids mark the wrong alert
    acknowledged and leave the one the analyst clicked still escalating.
    """
    monitor = NetworkMonitor()
    for i in range(502):
        monitor._emit_alert(
            "AEGIS-BEH-009",
            "LOW",
            "probe",
            "probe",
            "10.0.0.8",
            f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
            9,
            "",
            "e",
            "Discovery",
            "T1046",
        )
    ids = [a["id"] for a in monitor.alerts]
    assert len(ids) == 500
    assert len(set(ids)) == 500
    newest = monitor.alerts[-1]["id"]
    assert newest == "ALT-0502"
    assert monitor.acknowledge_alert(newest) is True
    assert monitor.alerts[-1]["acknowledged"] is True
    assert sum(1 for a in monitor.alerts if a["acknowledged"]) == 1
    print("[+] test_alert_ids_stay_unique_after_the_history_cap: PASSED")


if __name__ == "__main__":
    test_persistent_connection_is_not_c2_beaconing()
    test_reconnect_interval_is_c2_beaconing()
    test_smb_sessions_to_one_host_are_not_lateral_movement()
    test_smb_to_many_internal_hosts_is_lateral_movement()
    test_external_smb_is_not_lateral_movement()
    test_alert_ids_stay_unique_after_the_history_cap()
    print("\n[=== MONITOR DETECTION TESTS PASSED ===]")
