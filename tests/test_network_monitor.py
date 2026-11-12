"""Exfiltration paging must follow the learned baseline, not a fixed rate."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.monitor.network_monitor import NetworkMonitor

MB = 1024 * 1024


def _monitor() -> NetworkMonitor:
    mon = NetworkMonitor()
    # Record the decision without opening the alert router.
    mon._emit_alert = lambda **kwargs: mon.alerts.append(kwargs) or None
    return mon


def _feed(mon: NetworkMonitor, sent_rate: float, samples: int = 1):
    for _ in range(samples):
        mon._check_exfiltration(sent_rate, 0)


def test_steady_transfer_does_not_page():
    """A backup already running at monitor start is the baseline, not an incident."""
    mon = _monitor()
    _feed(mon, 40 * MB, 6)
    assert mon.alerts == []
    _feed(mon, 40 * MB, 3)
    assert mon.alerts == []
    # Jitter above a flat transfer stays inside the extra 10 MB/s band.
    _feed(mon, 45 * MB, 1)
    assert mon.alerts == []
    print("[+] test_steady_transfer_does_not_page: PASSED")


def test_warmup_suppresses_the_first_samples():
    mon = _monitor()
    _feed(mon, 80 * MB, 6)
    assert mon.alerts == []
    print("[+] test_warmup_suppresses_the_first_samples: PASSED")


def test_spike_above_quiet_baseline_pages():
    mon = _monitor()
    _feed(mon, 0.1 * MB, 6)
    assert mon.alerts == []
    _feed(mon, 20 * MB, 1)
    assert len(mon.alerts) == 1
    alert = mon.alerts[0]
    assert alert["pattern_id"] == "AEGIS-BEH-003"
    assert alert["severity"] == "CRITICAL"
    assert alert["tactic"] == "Exfiltration"
    print("[+] test_spike_above_quiet_baseline_pages: PASSED")


def test_sub_floor_bump_does_not_page():
    mon = _monitor()
    _feed(mon, 0.2 * MB, 6)
    _feed(mon, 2 * MB, 1)
    assert mon.alerts == []
    print("[+] test_sub_floor_bump_does_not_page: PASSED")


def test_jump_above_busy_baseline_pages():
    mon = _monitor()
    _feed(mon, 40 * MB, 6)
    _feed(mon, 55 * MB, 1)
    assert len(mon.alerts) == 1
    print("[+] test_jump_above_busy_baseline_pages: PASSED")


def test_negative_counter_reset_is_ignored():
    mon = _monitor()
    _feed(mon, 0.1 * MB, 6)
    mon._check_exfiltration(-50 * MB, 0)
    assert mon.alerts == []
    assert mon._egress_baseline.count == 6
    _feed(mon, 20 * MB, 1)
    assert len(mon.alerts) == 1
    print("[+] test_negative_counter_reset_is_ignored: PASSED")


if __name__ == "__main__":
    test_steady_transfer_does_not_page()
    test_warmup_suppresses_the_first_samples()
    test_spike_above_quiet_baseline_pages()
    test_sub_floor_bump_does_not_page()
    test_jump_above_busy_baseline_pages()
    test_negative_counter_reset_is_ignored()
    print("\n[=== EXFILTRATION BASELINE TESTS PASSED ===]")
