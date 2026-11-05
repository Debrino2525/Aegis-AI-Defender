"""Predictive analytics for attack prediction, risk forecasting, and resource optimization.

All maths use Python stdlib only (no scikit-learn / PyTorch required).
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# ATT&CK tactic chain knowledge base
# ---------------------------------------------------------------------------

# Maps a tactic to the most likely follow-on tactics (ordered by frequency)
_FOLLOWON: Dict[str, List[str]] = {
    "Reconnaissance":       ["Initial Access", "Resource Development"],
    "Resource Development": ["Initial Access"],
    "Initial Access":       ["Execution", "Persistence", "Defense Evasion"],
    "Execution":            ["Persistence", "Privilege Escalation", "Discovery"],
    "Persistence":          ["Privilege Escalation", "Defense Evasion", "Lateral Movement"],
    "Privilege Escalation": ["Defense Evasion", "Credential Access", "Lateral Movement"],
    "Defense Evasion":      ["Credential Access", "Discovery", "Lateral Movement"],
    "Credential Access":    ["Lateral Movement", "Discovery", "Exfiltration"],
    "Discovery":            ["Lateral Movement", "Collection", "Exfiltration"],
    "Lateral Movement":     ["Collection", "Command and Control", "Exfiltration"],
    "Collection":           ["Exfiltration", "Command and Control"],
    "Command and Control":  ["Exfiltration", "Impact"],
    "Exfiltration":         ["Impact"],
    "Impact":               [],
}

# Recommended preemptive response per predicted next tactic
_PREEMPTIVE: Dict[str, str] = {
    "Initial Access":       "Block inbound connections from flagged IPs; enforce MFA.",
    "Execution":            "Disable macro execution; monitor process creation on affected host.",
    "Persistence":          "Audit scheduled tasks and startup entries on affected host.",
    "Privilege Escalation": "Lock privileged accounts on affected host; review sudo rules.",
    "Defense Evasion":      "Enable enhanced audit logging; check AV/EDR health.",
    "Credential Access":    "Force password rotation for accounts on affected host.",
    "Discovery":            "Restrict internal subnet reachability from affected host.",
    "Lateral Movement":     "Isolate affected host to quarantine VLAN; block RDP/SMB/SSH.",
    "Collection":           "Revoke cloud-storage API tokens reachable from affected host.",
    "Command and Control":  "Block outbound traffic on non-standard ports from affected host.",
    "Exfiltration":         "Enable DLP rules; throttle outbound bandwidth on affected host.",
    "Impact":               "Activate IR playbook; snapshot affected systems immediately.",
    "Resource Development": "Threat-hunt lookalike domains registered in past 30 days.",
}

# CVE severity weights (CVSS 10-pt scale bucket -> risk multiplier)
_CVSS_WEIGHT = {
    "critical": 1.0,
    "high":     0.75,
    "medium":   0.4,
    "low":      0.1,
    "none":     0.0,
}

# ---------------------------------------------------------------------------
# Linear regression helper (pure Python, no numpy)
# ---------------------------------------------------------------------------

def _linear_regression(x: List[float], y: List[float]) -> Tuple[float, float]:
    """Return (slope, intercept) via ordinary least squares."""
    n = len(x)
    if n < 2:
        return 0.0, (y[0] if y else 0.0)
    sx = sum(x)
    sy = sum(y)
    sxx = sum(xi ** 2 for xi in x)
    sxy = sum(xi * yi for xi, yi in zip(x, y))
    denom = n * sxx - sx ** 2
    if denom == 0:
        return 0.0, sy / n
    slope = (n * sxy - sx * sy) / denom
    intercept = (sy - slope * sx) / n
    return slope, intercept


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class PredictiveAnalytics:
    """Predictive analytics for attack prediction and risk forecasting.

    Capabilities:
    - predict_next_attack: given an incident's tactic list, predict the next
      ATT&CK tactic and recommended preemptive response.
    - forecast_vulnerabilities: linear-regression trend on historical scan data.
    - optimize_resources: recommend scan concurrency / monitor throttle based
      on current system load.
    """

    def __init__(self):
        # Lightweight scan-history cache: list of {timestamp, critical, high, kev_rate}
        self._scan_history: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Attack prediction
    # ------------------------------------------------------------------

    def predict_next_attack(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Predict the next ATT&CK tactic and preemptive response.

        The incident dict should contain at least one of:
        - ``tactics``: list of tactic names already observed
        - ``tactic``: single tactic name (string)
        - ``phase``: kill-chain phase name

        Returns:
            Dict with keys: predicted_tactic, confidence, preemptive_response,
            full_chain, affected_host, incident_id.
        """
        # Extract tactic list
        tactics: List[str] = []
        if "tactics" in incident and isinstance(incident["tactics"], list):
            tactics = [str(t).strip() for t in incident["tactics"]]
        elif "tactic" in incident:
            tactics = [str(incident["tactic"]).strip()]
        elif "phase" in incident:
            tactics = [str(incident["phase"]).strip()]

        # Determine the last (most advanced) tactic
        last_tactic: Optional[str] = None
        for tactic in reversed(tactics):
            if tactic in _FOLLOWON:
                last_tactic = tactic
                break

        if last_tactic is None and tactics:
            # Unknown tactic name — do a fuzzy match (substring)
            normalized = tactics[-1].lower()
            for known in _FOLLOWON:
                if normalized in known.lower() or known.lower() in normalized:
                    last_tactic = known
                    break

        if last_tactic is None:
            # No recognisable tactic — default to Reconnaissance
            last_tactic = "Reconnaissance"

        followons = _FOLLOWON.get(last_tactic, [])
        if not followons:
            predicted = "Impact"
            confidence = 0.6
        else:
            predicted = followons[0]
            # Confidence is higher when fewer alternatives exist
            confidence = round(1.0 - 0.1 * min(len(followons) - 1, 5), 2)

        # Build projected full chain from last_tactic onward
        chain: List[str] = [last_tactic]
        seen: set = {last_tactic}
        current = last_tactic
        for _ in range(6):
            nexts = _FOLLOWON.get(current, [])
            if not nexts or nexts[0] in seen:
                break
            current = nexts[0]
            chain.append(current)
            seen.add(current)

        return {
            "incident_id": incident.get("id", incident.get("incident_id", "")),
            "affected_host": incident.get("host", incident.get("affected_host", "unknown")),
            "current_tactic": last_tactic,
            "predicted_tactic": predicted,
            "confidence": confidence,
            "preemptive_response": _PREEMPTIVE.get(predicted, "Review affected host."),
            "projected_chain": chain,
            "alternatives": followons[1:3],
            # keep legacy key for backwards compatibility
            "predicted_step": predicted,
            "timeframe": _estimate_timeframe(last_tactic),
        }

    # ------------------------------------------------------------------
    # Vulnerability forecasting
    # ------------------------------------------------------------------

    def ingest_scan_result(self, result: Dict[str, Any]) -> None:
        """Record a scan result for use by forecast_vulnerabilities.

        Args:
            result: Dict with keys: timestamp (unix epoch float), critical (int),
                    high (int), medium (int), low (int), kev_count (int),
                    total_assets (int).
        """
        entry = {
            "timestamp": float(result.get("timestamp", time.time())),
            "critical":  int(result.get("critical", 0)),
            "high":      int(result.get("high", 0)),
            "medium":    int(result.get("medium", 0)),
            "low":       int(result.get("low", 0)),
            "kev_count": int(result.get("kev_count", 0)),
            "total_assets": int(result.get("total_assets", 1)),
        }
        self._scan_history.append(entry)
        # Keep last 365 data points
        if len(self._scan_history) > 365:
            self._scan_history = self._scan_history[-365:]

    def forecast_vulnerabilities(
        self,
        time_horizon: int = 30,
    ) -> List[Dict[str, Any]]:
        """Forecast vulnerability counts over the next *time_horizon* days.

        Uses ordinary least-squares linear regression over the recorded scan
        history.  When fewer than 3 historical data points exist, returns a
        flat projection using the most recent values.

        Returns:
            List of dicts, one per day, each with keys:
            day, timestamp, critical_forecast, high_forecast,
            kev_forecast, trend (up/down/flat).
        """
        history = sorted(self._scan_history, key=lambda r: r["timestamp"])
        now = time.time()
        day_secs = 86_400.0

        if len(history) < 3:
            # Flat projection from latest values
            last = history[-1] if history else {"critical": 0, "high": 0, "kev_count": 0}
            return [
                {
                    "day": d + 1,
                    "timestamp": now + (d + 1) * day_secs,
                    "critical_forecast": int(last.get("critical", 0)),
                    "high_forecast":     int(last.get("high", 0)),
                    "kev_forecast":      int(last.get("kev_count", 0)),
                    "trend": "flat",
                }
                for d in range(time_horizon)
            ]

        # Normalise x to days-since-first-record
        t0 = history[0]["timestamp"]
        xs = [(r["timestamp"] - t0) / day_secs for r in history]
        last_x = xs[-1]

        forecasts = []
        for metric, label in [("critical", "critical_forecast"),
                               ("high",     "high_forecast"),
                               ("kev_count","kev_forecast")]:
            ys = [float(r[metric]) for r in history]
            slope, intercept = _linear_regression(xs, ys)
            forecasts.append((label, slope, intercept))

        results = []
        for d in range(time_horizon):
            future_x = last_x + d + 1
            row: Dict[str, Any] = {
                "day": d + 1,
                "timestamp": now + (d + 1) * day_secs,
            }
            for label, slope, intercept in forecasts:
                raw = slope * future_x + intercept
                row[label] = max(0, int(round(raw)))
            # Overall trend from slope of critical count
            crit_slope = forecasts[0][1]
            if crit_slope > 0.1:
                row["trend"] = "up"
            elif crit_slope < -0.1:
                row["trend"] = "down"
            else:
                row["trend"] = "flat"
            results.append(row)
        return results

    # ------------------------------------------------------------------
    # Resource optimisation
    # ------------------------------------------------------------------

    def optimize_resources(
        self,
        current_load: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Recommend scan concurrency and monitor throttle based on system load.

        Args:
            current_load: Dict with optional keys cpu_percent, memory_percent,
                          active_scans, active_agents.

        Returns:
            Dict with keys: recommended_concurrency, throttle_monitors,
            pause_non_critical, reasoning.
        """
        cpu  = float(current_load.get("cpu_percent",    0.0))
        mem  = float(current_load.get("memory_percent", 0.0))
        scans = int(current_load.get("active_scans",    1))
        agents = int(current_load.get("active_agents",  0))

        pressure = max(cpu, mem)
        reasoning: List[str] = []

        if pressure > 85:
            recommended_concurrency = max(1, scans // 2)
            throttle_monitors = True
            pause_non_critical = True
            reasoning.append(
                f"System pressure {pressure:.0f}% — halving scan concurrency, "
                "pausing non-critical monitors."
            )
        elif pressure > 65:
            recommended_concurrency = max(1, int(scans * 0.75))
            throttle_monitors = False
            pause_non_critical = False
            reasoning.append(
                f"System pressure {pressure:.0f}% — reducing concurrency by 25%."
            )
        else:
            recommended_concurrency = max(scans, 4)  # allow more if headroom exists
            throttle_monitors = False
            pause_non_critical = False
            reasoning.append(
                f"System pressure {pressure:.0f}% — no throttling needed."
            )

        if agents > 50:
            reasoning.append(
                f"{agents} agents connected — recommend staggering heartbeat intervals."
            )

        return {
            "recommended_concurrency": recommended_concurrency,
            "throttle_monitors":       throttle_monitors,
            "pause_non_critical":      pause_non_critical,
            "cpu_percent":             cpu,
            "memory_percent":          mem,
            "reasoning":               " ".join(reasoning),
        }

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def risk_score(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute an aggregate risk score for a list of scan findings.

        Args:
            findings: List of dicts with keys: severity, is_kev, epss_score.

        Returns:
            Dict with keys: score (0-100), grade (A-F), breakdown.
        """
        if not findings:
            return {"score": 0, "grade": "A", "breakdown": {}}

        total = 0.0
        breakdown: Dict[str, int] = defaultdict(int)
        for f in findings:
            sev = str(f.get("severity", "medium")).lower()
            weight = _CVSS_WEIGHT.get(sev, 0.4)
            kev_bonus = 0.3 if f.get("is_kev") else 0.0
            epss = float(f.get("epss_score", 0.0))
            total += (weight + kev_bonus) * (1 + epss)
            breakdown[sev] += 1

        # Normalise to 0-100 (cap at 100)
        normalised = min(100, int(total * 10))
        grade = (
            "A" if normalised < 20 else
            "B" if normalised < 40 else
            "C" if normalised < 60 else
            "D" if normalised < 80 else
            "F"
        )
        return {
            "score":     normalised,
            "grade":     grade,
            "breakdown": dict(breakdown),
            "finding_count": len(findings),
        }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _estimate_timeframe(tactic: str) -> str:
    """Rough empirical dwell-time before a follow-on tactic typically fires."""
    fast = {"Execution", "Credential Access", "Impact"}
    slow = {"Reconnaissance", "Resource Development", "Persistence"}
    if tactic in fast:
        return "minutes to 2 hours"
    if tactic in slow:
        return "days to weeks"
    return "2–24 hours"
