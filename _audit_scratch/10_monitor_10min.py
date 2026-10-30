#!/usr/bin/env python3
"""Part 4.2-4.3: 10-minute NetworkMonitor run, snapshot every 30s, log every alert."""
import asyncio
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "10_monitor_10min.json"
SNAP = Path(__file__).resolve().parent / "results" / "10_snapshots.jsonl"

import psutil
from aegis.monitor.network_monitor import NetworkMonitor

DURATION_S = float(os.environ.get("AEGIS_AUDIT_MONITOR_S", "600"))
INTERVAL_S = float(os.environ.get("AEGIS_AUDIT_SNAPSHOT_S", "30"))


def rss_and_cpu(proc: psutil.Process):
    mem = proc.memory_info()
    cpu = proc.cpu_percent(interval=None)
    return mem.rss, cpu


async def main():
    proc = psutil.Process(os.getpid())
    proc.cpu_percent(interval=None)  # prime
    mon = NetworkMonitor()
    await mon.start()
    t0 = time.time()
    snapshots = []
    seen_ids = set()
    alerts_log = []
    SNAP.write_text("")

    while True:
        now = time.time()
        elapsed = now - t0
        rss, cpu = rss_and_cpu(proc)
        snap = {
            "elapsed_s": elapsed,
            "wall": now,
            "rss_bytes": rss,
            "cpu_percent": cpu,
            "len_conn_history": len(mon.conn_history),
            "len_alerts": len(mon.alerts),
            "len_seen_alert_keys": len(mon.seen_alert_keys),
            "len_graph_nodes": len(mon.graph_nodes),
            "len_graph_edges": len(mon.graph_edges),
            "len_current_connections": len(mon.current_connections),
            "stats": dict(mon.stats),
        }
        snapshots.append(snap)
        with SNAP.open("a") as f:
            f.write(json.dumps(snap) + "\n")

        for a in mon.alerts:
            aid = a.get("id")
            if aid not in seen_ids:
                seen_ids.add(aid)
                alerts_log.append({
                    "id": aid,
                    "elapsed_s": elapsed,
                    "pattern_id": a.get("pattern_id"),
                    "severity": a.get("severity"),
                    "title": a.get("title"),
                    "source_ip": a.get("source_ip"),
                    "dest_ip": a.get("dest_ip"),
                    "dest_port": a.get("dest_port"),
                    "process": a.get("process"),
                    "evidence": a.get("evidence"),
                    "tactic": a.get("tactic"),
                })

        if elapsed >= DURATION_S:
            break
        await asyncio.sleep(INTERVAL_S)

    mon.stop()
    # one last drain
    await asyncio.sleep(0.2)

    n_min = DURATION_S / 60.0
    payload = {
        "duration_s": DURATION_S,
        "snapshot_interval_s": INTERVAL_S,
        "n_snapshots": len(snapshots),
        "snapshots": snapshots,
        "alerts": alerts_log,
        "alerts_per_minute": (len(alerts_log) / n_min) if n_min else None,
        "growth": {
            "rss_first": snapshots[0]["rss_bytes"] if snapshots else None,
            "rss_last": snapshots[-1]["rss_bytes"] if snapshots else None,
            "conn_history_first": snapshots[0]["len_conn_history"] if snapshots else None,
            "conn_history_last": snapshots[-1]["len_conn_history"] if snapshots else None,
            "alerts_first": snapshots[0]["len_alerts"] if snapshots else None,
            "alerts_last": snapshots[-1]["len_alerts"] if snapshots else None,
            "seen_alert_keys_first": snapshots[0]["len_seen_alert_keys"] if snapshots else None,
            "seen_alert_keys_last": snapshots[-1]["len_seen_alert_keys"] if snapshots else None,
            "graph_nodes_first": snapshots[0]["len_graph_nodes"] if snapshots else None,
            "graph_nodes_last": snapshots[-1]["len_graph_nodes"] if snapshots else None,
            "graph_edges_first": snapshots[0]["len_graph_edges"] if snapshots else None,
            "graph_edges_last": snapshots[-1]["len_graph_edges"] if snapshots else None,
        },
        "conn_history_keys_sample": [
            [k[0], k[1], k[2], len(v)] for k, v in list(mon.conn_history.items())[:30]
        ],
        "final_current_connections": [
            {kk: c[kk] for kk in ("local_ip", "remote_ip", "remote_port", "status", "process") if kk in c}
            for c in mon.current_connections[:50]
        ],
    }
    OUT.write_text(json.dumps(payload, indent=2, default=str))
    print(json.dumps({
        "n_snapshots": payload["n_snapshots"],
        "n_alerts": len(alerts_log),
        "alerts_per_minute": payload["alerts_per_minute"],
        "growth": payload["growth"],
        "alert_titles": [(a["pattern_id"], a["severity"], a["title"]) for a in alerts_log],
    }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
