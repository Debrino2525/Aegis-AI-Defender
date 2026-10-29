"""
Behavioral Baseline Engine.
Learns normal network behavior for each host and scores deviation in real-time.
Uses rolling statistics: mean, standard deviation, min/max per metric per host.
"""

import math
import time
from typing import Dict, Any, Optional
from collections import defaultdict, deque


class RollingStats:
    """Maintains rolling mean and standard deviation over a sliding window."""

    def __init__(self, window: int = 60):
        self.window = window
        self.values: deque = deque(maxlen=window)

    def add(self, value: float):
        self.values.append(value)

    @property
    def mean(self) -> float:
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)

    @property
    def stddev(self) -> float:
        if len(self.values) < 2:
            return 0.0
        m = self.mean
        variance = sum((v - m) ** 2 for v in self.values) / len(self.values)
        return math.sqrt(variance)

    @property
    def count(self) -> int:
        return len(self.values)

    def z_score(self, value: float) -> float:
        """How many standard deviations is this value from the mean?"""
        sd = self.stddev
        if sd == 0:
            return 0.0
        return abs(value - self.mean) / sd

    def is_anomalous(self, value: float, threshold_z: float = 2.5) -> bool:
        """Returns True if value deviates significantly from the baseline."""
        if self.count < 5:
            return False  # Not enough data yet
        return self.z_score(value) >= threshold_z


class HostBaseline:
    """
    Behavioral baseline for a single host.
    Tracks: connection rate, bytes sent, bytes received, unique destinations,
    unique ports, DNS query rate, auth connection rate.
    """

    def __init__(self, host: str):
        self.host = host
        self.first_seen = time.time()
        self.last_seen = time.time()

        # Rolling stats (per 10-second sample)
        self.conn_rate = RollingStats(window=30)          # new connections/10s
        self.bytes_sent_rate = RollingStats(window=30)    # bytes sent/10s
        self.bytes_recv_rate = RollingStats(window=30)    # bytes recv/10s
        self.unique_ports = RollingStats(window=30)       # unique dst ports/10s
        self.unique_dsts = RollingStats(window=30)        # unique dst IPs/10s
        self.smb_targets = RollingStats(window=30)        # SMB connections/10s
        self.auth_conns = RollingStats(window=30)         # SSH/RDP/SMTP conns/10s

        # Seen history (for novelty detection)
        self.known_destinations: set = set()
        self.known_ports: set = set()
        self.internal_connections: set = set()

        # Anomaly scoring
        self.anomaly_score: float = 0.0
        self.alert_count: int = 0

    def update(self, sample: Dict[str, Any]):
        """Updates baseline with a new 10-second observation sample."""
        self.last_seen = time.time()

        self.conn_rate.add(sample.get("new_connections", 0))
        self.bytes_sent_rate.add(sample.get("bytes_sent_delta", 0))
        self.bytes_recv_rate.add(sample.get("bytes_recv_delta", 0))
        self.unique_ports.add(sample.get("unique_ports_count", 0))
        self.unique_dsts.add(sample.get("unique_destinations", 0))
        self.smb_targets.add(sample.get("smb_connections", 0))
        self.auth_conns.add(sample.get("auth_connections", 0))

        # Update known destinations and ports
        for dst in sample.get("destinations", []):
            self.known_destinations.add(dst)
        for port in sample.get("ports", []):
            self.known_ports.add(port)

    def score_anomaly(self, sample: Dict[str, Any]) -> float:
        """
        Compute overall anomaly score (0.0–100.0) for a new sample.
        Higher = more anomalous vs baseline.
        """
        scores = []

        metrics = [
            ("new_connections", self.conn_rate, 2.5),
            ("bytes_sent_delta", self.bytes_sent_rate, 3.0),
            ("unique_ports_count", self.unique_ports, 2.5),
            ("unique_destinations", self.unique_dsts, 2.5),
            ("smb_connections", self.smb_targets, 2.0),
            ("auth_connections", self.auth_conns, 2.0),
        ]

        for key, stat, threshold in metrics:
            if stat.count >= 5:
                z = stat.z_score(sample.get(key, 0))
                normalized = min(100.0, (z / max(threshold, 0.1)) * 50)
                scores.append(normalized)

        if not scores:
            return 0.0
        return round(min(100.0, sum(scores) / len(scores)), 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "baseline_samples": self.conn_rate.count,
            "avg_conn_rate": round(self.conn_rate.mean, 2),
            "avg_bytes_sent": round(self.bytes_sent_rate.mean, 0),
            "known_destinations": len(self.known_destinations),
            "known_ports": len(self.known_ports),
            "anomaly_score": self.anomaly_score,
            "alert_count": self.alert_count,
            "established": self.conn_rate.count >= 5,
        }


class BehavioralEngine:
    """
    Manages baselines for all observed hosts and detects anomalies.
    """

    def __init__(self):
        self.baselines: Dict[str, HostBaseline] = {}

    def get_or_create(self, host: str) -> HostBaseline:
        if host not in self.baselines:
            self.baselines[host] = HostBaseline(host)
        return self.baselines[host]

    def update_and_score(self, host: str, sample: Dict[str, Any]) -> float:
        baseline = self.get_or_create(host)
        score = baseline.score_anomaly(sample)
        baseline.update(sample)
        baseline.anomaly_score = score
        return score

    def get_all_baselines(self) -> list:
        return [b.to_dict() for b in self.baselines.values()]

    def is_new_destination(self, host: str, dst: str) -> bool:
        baseline = self.baselines.get(host)
        if not baseline or baseline.conn_rate.count < 3:
            return False
        return dst not in baseline.known_destinations

    def is_new_port(self, host: str, port: int) -> bool:
        baseline = self.baselines.get(host)
        if not baseline or baseline.unique_ports.count < 3:
            return False
        return port not in baseline.known_ports
