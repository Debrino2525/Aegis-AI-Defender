#!/usr/bin/env python3
"""Part 4.1: time net_connections and Process.name lookups; p50/p95/max of 100 _sample_connections calls."""
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "09_sample_timing.json"

import psutil
from aegis.monitor.network_monitor import NetworkMonitor


def pct(xs, p):
    if not xs:
        return None
    ys = sorted(xs)
    k = (len(ys) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(ys) - 1)
    if f == c:
        return ys[f]
    return ys[f] + (ys[c] - ys[f]) * (k - f)


def time_net_connections(n=20):
    times = []
    counts = []
    for _ in range(n):
        t0 = time.perf_counter()
        conns = psutil.net_connections(kind="inet")
        times.append(time.perf_counter() - t0)
        counts.append(len(conns))
    return times, counts


def time_proc_name_lookups():
    conns = psutil.net_connections(kind="inet")
    per = []
    errors = 0
    named = 0
    for conn in conns:
        if not conn.pid:
            continue
        t0 = time.perf_counter()
        try:
            psutil.Process(conn.pid).name()
            named += 1
        except Exception:
            errors += 1
        per.append(time.perf_counter() - t0)
    return {
        "connection_count": len(conns),
        "lookups_attempted": len(per),
        "named_ok": named,
        "errors": errors,
        "per_lookup_s": per,
        "total_lookup_s": sum(per) if per else 0.0,
        "p50": pct(per, 50) if per else None,
        "p95": pct(per, 95) if per else None,
        "max": max(per) if per else None,
    }


async def time_samples(n=100):
    mon = NetworkMonitor()
    # do not start loops
    times = []
    conn_counts = []
    for _ in range(n):
        t0 = time.perf_counter()
        await mon._sample_connections()
        times.append(time.perf_counter() - t0)
        conn_counts.append(len(mon.current_connections))
    return times, conn_counts, mon


async def event_loop_block_probe():
    """Measure how long the event loop is occupied during one _sample_connections."""
    mon = NetworkMonitor()
    ping_gaps = []

    async def pinger(stop):
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(0)
            now = time.perf_counter()
            ping_gaps.append(now - last)
            last = now

    stop = asyncio.Event()
    t = asyncio.create_task(pinger(stop))
    await asyncio.sleep(0.05)
    t0 = time.perf_counter()
    await mon._sample_connections()
    sample_s = time.perf_counter() - t0
    await asyncio.sleep(0.05)
    stop.set()
    t.cancel()
    return {
        "sample_s": sample_s,
        "max_ping_gap_s": max(ping_gaps) if ping_gaps else None,
        "p95_ping_gap_s": pct(ping_gaps, 95) if ping_gaps else None,
        "n_pings": len(ping_gaps),
    }


async def main():
    nc_times, nc_counts = time_net_connections(20)
    proc = time_proc_name_lookups()
    sample_times, sample_counts, mon = await time_samples(100)
    loop_block = await event_loop_block_probe()
    payload = {
        "net_connections": {
            "n": 20,
            "counts": nc_counts,
            "times_s": nc_times,
            "p50": pct(nc_times, 50),
            "p95": pct(nc_times, 95),
            "max": max(nc_times),
            "min": min(nc_times),
        },
        "process_name_lookups": proc,
        "sample_connections_100": {
            "times_s": sample_times,
            "p50": pct(sample_times, 50),
            "p95": pct(sample_times, 95),
            "max": max(sample_times),
            "min": min(sample_times),
            "mean": statistics.mean(sample_times),
            "conn_counts_after_loopback_filter": sample_counts,
            "len_conn_history_after": len(mon.conn_history),
            "len_alerts_after": len(mon.alerts),
            "len_seen_alert_keys": len(mon.seen_alert_keys),
        },
        "event_loop_block_probe": loop_block,
        "note": "Process.name() runs on the event loop after net_connections is awaited via executor",
    }
    OUT.write_text(json.dumps(payload, indent=2))
    print(json.dumps({k: v for k, v in payload.items() if k != "sample_connections_100"} | {
        "sample_connections_100": {kk: vv for kk, vv in payload["sample_connections_100"].items() if kk != "times_s"} | {
            "times_s_len": len(payload["sample_connections_100"]["times_s"]),
            "times_s": payload["sample_connections_100"]["times_s"],
        }
    }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
