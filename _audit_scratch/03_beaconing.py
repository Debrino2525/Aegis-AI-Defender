#!/usr/bin/env python3
"""Part 2A: reproduce C2 beaconing on a persistent ESTABLISHED connection via real _sample_connections."""
import asyncio
import json
import socket
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "03_beaconing.json"

import psutil
from aegis.monitor.network_monitor import NetworkMonitor, is_loopback, is_private_ip


def pick_non_loopback():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    return None


async def hold_and_sample_real(bind_ip: str, port: int, n_samples: int, sleep_s: float):
    """Start a TCP listener, hold one client connection, sample with the real monitor path."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_ip, port))
    srv.listen(1)
    srv.setblocking(False)

    loop = asyncio.get_event_loop()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3)
    client.connect((bind_ip, port))
    conn_sock, _ = await loop.sock_accept(srv)

    mon = NetworkMonitor()
    sample_times = []
    for i in range(n_samples):
        t0 = time.perf_counter()
        await mon._sample_connections()
        sample_times.append(time.perf_counter() - t0)
        if i < n_samples - 1:
            await asyncio.sleep(sleep_s)

    # Inspect history for this 5-tuple
    matching_keys = []
    for key, ts in mon.conn_history.items():
        src, dst, dport = key
        if dport == port and (dst == bind_ip or src == bind_ip):
            matching_keys.append({
                "key": [src, dst, dport],
                "n_timestamps": len(ts),
                "timestamps": ts,
                "intervals": [ts[i + 1] - ts[i] for i in range(len(ts) - 1)],
            })

    alerts = [a for a in mon.alerts if a.get("pattern_id") == "AEGIS-BEH-002"]
    client.close()
    conn_sock.close()
    srv.close()
    return {
        "bind_ip": bind_ip,
        "port": port,
        "n_samples": n_samples,
        "sleep_s": sleep_s,
        "sample_durations_s": sample_times,
        "matching_history": matching_keys,
        "beh002_alerts": [
            {k: a[k] for k in ("id", "pattern_id", "severity", "title", "evidence", "dest_ip", "dest_port") if k in a}
            for a in alerts
        ],
        "all_alert_pattern_ids": [a.get("pattern_id") for a in mon.alerts],
        "n_current_connections_last_sample": len(mon.current_connections),
    }


async def synthetic_injected_history():
    """Call the real _check_beaconing after appending timestamps the same way _sample_connections does."""
    mon = NetworkMonitor()
    src, dst, port = "172.30.0.2", "8.8.8.8", 443
    now = time.time()
    # Mimic SAMPLE_INTERVAL=5 appends for a long-lived flow
    key = (src, dst, port)
    for i in range(6):
        mon.conn_history[key].append(now + i * 5.0)
    mon._check_beaconing(src, {dst}, now + 25.0)
    alerts = [a for a in mon.alerts if a.get("pattern_id") == "AEGIS-BEH-002"]
    ts = mon.conn_history[key]
    intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    avg = sum(intervals) / len(intervals)
    stddev = (sum((x - avg) ** 2 for x in intervals) / len(intervals)) ** 0.5
    return {
        "method": "inject timestamps every 5.0s then call _check_beaconing",
        "n_timestamps": len(ts),
        "intervals": intervals,
        "avg_interval": avg,
        "stddev": stddev,
        "condition_stddev_lt_5": stddev < 5.0,
        "condition_5_lt_avg_lt_300": 5 < avg < 300,
        "would_emit": bool(alerts),
        "alerts": [
            {k: a[k] for k in ("pattern_id", "severity", "title", "evidence")}
            for a in alerts
        ],
    }


async def boundary_avg_exactly_5():
    """If avg_interval is exactly 5.0, `5 < avg` fails."""
    mon = NetworkMonitor()
    src, dst, port = "10.0.0.1", "1.2.3.4", 443
    now = time.time()
    key = (src, dst, port)
    for i in range(6):
        mon.conn_history[key].append(now + i * 5.0)
    ts = mon.conn_history[key]
    intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    avg = sum(intervals) / len(intervals)
    mon._check_beaconing(src, {dst}, now + 25)
    return {
        "avg_interval": avg,
        "strict_gt_5": avg > 5,
        "emitted": any(a.get("pattern_id") == "AEGIS-BEH-002" for a in mon.alerts),
    }


async def jittered_5_1():
    """Real asyncio.sleep(5) + work typically yields avg slightly > 5."""
    mon = NetworkMonitor()
    src, dst, port = "10.0.0.1", "9.9.9.9", 443
    t0 = time.time()
    for i in range(6):
        mon.conn_history[(src, dst, port)].append(time.time())
        if i < 5:
            await asyncio.sleep(5.0)
    ts = mon.conn_history[(src, dst, port)]
    intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    avg = sum(intervals) / len(intervals)
    stddev = (sum((x - avg) ** 2 for x in intervals) / len(intervals)) ** 0.5
    mon._check_beaconing(src, {dst}, time.time())
    return {
        "wall_s": time.time() - t0,
        "intervals": intervals,
        "avg_interval": avg,
        "stddev": stddev,
        "emitted": any(a.get("pattern_id") == "AEGIS-BEH-002" for a in mon.alerts),
        "alert_titles": [a["title"] for a in mon.alerts if a.get("pattern_id") == "AEGIS-BEH-002"],
        "evidence": [a.get("evidence") for a in mon.alerts if a.get("pattern_id") == "AEGIS-BEH-002"],
    }


async def main():
    bind_ip = pick_non_loopback()
    real_path = None
    real_err = None
    if bind_ip:
        try:
            # port 8080 is in the beacon port list
            real_path = await hold_and_sample_real(bind_ip, 8080, n_samples=6, sleep_s=5.0)
        except Exception as e:
            real_err = repr(e)
    else:
        real_err = "no non-loopback IPv4 address"

    injected = await synthetic_injected_history()
    boundary = await boundary_avg_exactly_5()
    jitter = await jittered_5_1()

    payload = {
        "bind_ip": bind_ip,
        "loopback_skipped_by_monitor": True,
        "real_sample_path": real_path,
        "real_sample_error": real_err,
        "injected_exact_5s": injected,
        "boundary_avg_exactly_5": boundary,
        "real_sleep_5s_timestamps": jitter,
    }
    OUT.write_text(json.dumps(payload, indent=2, default=str))
    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
