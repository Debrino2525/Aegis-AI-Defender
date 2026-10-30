#!/usr/bin/env python3
"""Part 2B: RollingStats.z_score, score_anomaly averaging, 100x spike vs threshold 75."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "02_behavioral.json"

from aegis.monitor.behavioral_engine import RollingStats, HostBaseline, BehavioralEngine

rows = []

# stddev == 0 cases
for label, values, probe in [
    ("empty", [], 100),
    ("single", [5.0], 100),
    ("flat5", [5.0] * 10, 500),
    ("flat0", [0.0] * 10, 100),
    ("varied", [1.0, 2.0, 3.0, 4.0, 5.0], 100),
]:
    s = RollingStats(window=30)
    for v in values:
        s.add(v)
    z = s.z_score(probe)
    rows.append({
        "case": label,
        "values": values,
        "probe": probe,
        "mean": s.mean,
        "stddev": s.stddev,
        "count": s.count,
        "z_score": z,
        "is_anomalous": s.is_anomalous(probe, 2.5),
    })

# 100x spike in ONE metric after a flat baseline of 5 samples (count>=5 required)
# Baseline: new_connections=1, all other metrics 0, for 10 samples
base = HostBaseline("10.0.0.5")
flat = {
    "new_connections": 1,
    "bytes_sent_delta": 0,
    "bytes_recv_delta": 0,
    "unique_ports_count": 1,
    "unique_destinations": 1,
    "smb_connections": 0,
    "auth_connections": 0,
    "destinations": ["1.1.1.1"],
    "ports": [443],
}
for _ in range(10):
    base.update(flat)

# score is computed BEFORE update in update_and_score; replicate that
spike = dict(flat)
spike["new_connections"] = 100  # 100x vs mean 1
score_100x_one_metric = base.score_anomaly(spike)

# Per-metric breakdown
breakdown = []
metrics = [
    ("new_connections", base.conn_rate, 2.5),
    ("bytes_sent_delta", base.bytes_sent_rate, 3.0),
    ("unique_ports_count", base.unique_ports, 2.5),
    ("unique_destinations", base.unique_dsts, 2.5),
    ("smb_connections", base.smb_targets, 2.0),
    ("auth_connections", base.auth_conns, 2.0),
]
for key, stat, threshold in metrics:
    z = stat.z_score(spike.get(key, 0))
    normalized = min(100.0, (z / max(threshold, 0.1)) * 50)
    breakdown.append({
        "key": key,
        "sample": spike.get(key, 0),
        "mean": stat.mean,
        "stddev": stat.stddev,
        "count": stat.count,
        "z": z,
        "threshold": threshold,
        "normalized": normalized,
    })

# Also: 100x on bytes_sent_delta which is always 0 in production samples
spike_bytes = dict(flat)
spike_bytes["bytes_sent_delta"] = 0  # still 0
score_bytes_still_zero = base.score_anomaly(spike_bytes)

# What if bytes actually spiked 100x from a non-zero baseline
base2 = HostBaseline("10.0.0.6")
nonzero = dict(flat)
nonzero["bytes_sent_delta"] = 1000
for _ in range(10):
    base2.update(nonzero)
spike_b = dict(nonzero)
spike_b["bytes_sent_delta"] = 100000
score_bytes_100x_if_tracked = base2.score_anomaly(spike_b)

# Confirm averaging: if 5 metrics score 0 and 1 scores X, result is X/6
engine = BehavioralEngine()
# insufficient samples -> 0
early = engine.update_and_score("h1", flat)

payload = {
    "z_score_cases": rows,
    "alert_threshold_in__check_behavioral_anomaly": 75.0,
    "flat_baseline_samples": 10,
    "score_100x_spike_in_new_connections_only": score_100x_one_metric,
    "would_alert_at_75": score_100x_one_metric >= 75.0,
    "would_alert_at_45": score_100x_one_metric >= 45.0,
    "per_metric_breakdown_for_100x_conn": breakdown,
    "score_when_bytes_remain_0": score_bytes_still_zero,
    "score_100x_bytes_if_bytes_were_tracked": score_bytes_100x_if_tracked,
    "score_with_fewer_than_5_samples": early,
    "averaging_note": "score_anomaly returns sum(scores)/len(scores) over metrics with count>=5",
}
OUT.write_text(json.dumps(payload, indent=2))
print(json.dumps(payload, indent=2))
