"""Unsupervised learning for anomaly detection, reinforcement learning, and federated aggregation.

All maths use Python stdlib + optional numpy (falls back to pure-Python if not installed).
No PyTorch / TensorFlow / scikit-learn required.
"""

from __future__ import annotations

import math
import time
import uuid
import statistics
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional numpy — pure-Python fallback used when it is absent
# ---------------------------------------------------------------------------
try:
    import numpy as np  # type: ignore
    _HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore
    _HAS_NUMPY = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _stddev(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((v - m) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _z_score(value: float, mean: float, std: float) -> float:
    if std == 0.0:
        return 0.0
    return abs(value - mean) / std


# ---------------------------------------------------------------------------
# Z-score anomaly model (stored per model_id)
# ---------------------------------------------------------------------------

class _ZScoreModel:
    """Per-feature rolling statistics for one trained model."""

    def __init__(self, threshold_z: float = 2.5, window: int = 200):
        self.threshold_z = threshold_z
        self.window = window
        # feature_name -> deque of floats
        self.windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window))
        self.stats: Dict[str, Tuple[float, float]] = {}  # feature -> (mean, std)
        self.trained = False
        self.trained_at: float = 0.0

    # ------------------------------------------------------------------
    def fit(self, records: List[Dict[str, Any]]) -> None:
        """Compute per-feature mean + std from training records."""
        feature_values: Dict[str, List[float]] = defaultdict(list)
        for rec in records:
            for key, val in rec.items():
                try:
                    feature_values[key].append(float(val))
                except (TypeError, ValueError):
                    pass
        for feat, vals in feature_values.items():
            self.stats[feat] = (_mean(vals), _stddev(vals))
            # Seed the rolling window with training data (last `window` points)
            for v in vals[-self.window:]:
                self.windows[feat].append(v)
        self.trained = bool(self.stats)
        self.trained_at = time.time()

    # ------------------------------------------------------------------
    def score(self, sample: Dict[str, Any]) -> Tuple[bool, Dict[str, float]]:
        """Return (is_anomalous, {feature: z_score}) for numeric features in sample."""
        z_scores: Dict[str, float] = {}
        for key, val in sample.items():
            try:
                fval = float(val)
            except (TypeError, ValueError):
                continue
            if key in self.stats:
                mean, std = self.stats[key]
            elif key in self.windows and len(self.windows[key]) >= 5:
                vals = list(self.windows[key])
                mean, std = _mean(vals), _stddev(vals)
            else:
                continue
            z = _z_score(fval, mean, std)
            z_scores[key] = round(z, 4)
            # Update rolling window for online learning
            self.windows[key].append(fval)
            # Update running stats
            vals = list(self.windows[key])
            self.stats[key] = (_mean(vals), _stddev(vals))

        anomalous = any(z >= self.threshold_z for z in z_scores.values())
        return anomalous, z_scores


# ---------------------------------------------------------------------------
# Q-table for Reinforcement Learning
# ---------------------------------------------------------------------------

ACTIONS = ("observe", "recommend", "auto")

class _QTable:
    """Tabular Q-learning for response-action selection.

    State is a discrete tuple derived from (severity_bucket, confidence_bucket, is_kev).
    Q-values are updated from outcome feedback (reward).
    """

    def __init__(self, alpha: float = 0.1, gamma: float = 0.9, epsilon: float = 0.15):
        self.alpha = alpha      # learning rate
        self.gamma = gamma      # discount factor
        self.epsilon = epsilon  # exploration rate
        self.q: Dict[Tuple, Dict[str, float]] = defaultdict(lambda: {a: 0.0 for a in ACTIONS})
        self.history: deque = deque(maxlen=500)  # (state, action, reward, next_state)

    # ------------------------------------------------------------------
    def _discretize(self, state: Dict[str, Any]) -> Tuple:
        severity = str(state.get("severity", "medium")).lower()
        sev_bucket = {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(severity, 1)
        conf = float(state.get("confidence", 0.5))
        conf_bucket = int(min(conf * 4, 3))  # 0-3
        is_kev = int(bool(state.get("is_kev", False)))
        host_risk = int(min(float(state.get("host_risk", 0.5)) * 2, 1))  # 0 or 1
        return (sev_bucket, conf_bucket, is_kev, host_risk)

    # ------------------------------------------------------------------
    def select_action(self, state: Dict[str, Any]) -> str:
        import random
        s = self._discretize(state)
        if random.random() < self.epsilon:
            return random.choice(ACTIONS)
        q_vals = self.q[s]
        return max(q_vals, key=q_vals.__getitem__)

    # ------------------------------------------------------------------
    def update(self, state: Dict[str, Any], action: str, reward: float,
               next_state: Dict[str, Any]) -> None:
        s = self._discretize(state)
        ns = self._discretize(next_state)
        best_next = max(self.q[ns].values())
        old = self.q[s][action]
        self.q[s][action] = old + self.alpha * (reward + self.gamma * best_next - old)
        self.history.append((s, action, reward, ns))

    # ------------------------------------------------------------------
    def q_values(self, state: Dict[str, Any]) -> Dict[str, float]:
        s = self._discretize(state)
        return dict(self.q[s])


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class UnsupervisedLearning:
    """Unsupervised learning models for anomaly detection without labels.

    Capabilities:
    - train_anomaly_detector: fit a z-score model on a list of numeric records
    - detect_anomaly: score a sample against a trained model
    - reinforcement_learning: Q-table agent selects observe/recommend/auto
    - federated_learning: federated averaging of per-agent baselines
    """

    def __init__(self):
        # model_id -> _ZScoreModel
        self._models: Dict[str, _ZScoreModel] = {}
        # Shared Q-table for response selection
        self._qtable = _QTable()
        # Federated round counter
        self._fed_round = 0
        # Global federated baseline (feature -> (mean, std))
        self._global_baseline: Dict[str, Tuple[float, float]] = {}

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def train_anomaly_detector(
        self,
        data: List[Dict[str, Any]],
        threshold_z: float = 2.5,
        window: int = 200,
    ) -> str:
        """Fit a z-score anomaly model on *data* and return a model_id.

        Args:
            data: List of dicts with numeric fields (e.g. connection counts, bytes).
            threshold_z: Z-score threshold for anomaly classification.
            window: Rolling window size for online updates after training.

        Returns:
            Opaque model_id string.
        """
        if not data:
            raise ValueError("data must be a non-empty list of dicts")
        model = _ZScoreModel(threshold_z=threshold_z, window=window)
        model.fit(data)
        model_id = f"zscore-{uuid.uuid4().hex[:8]}"
        self._models[model_id] = model
        return model_id

    def detect_anomaly(
        self,
        model_id: str,
        sample: Dict[str, Any],
    ) -> bool:
        """Return True if *sample* is anomalous according to the named model.

        If the model_id is unknown the sample is scored against the global
        federated baseline (if available), otherwise returns False.
        """
        model = self._models.get(model_id)
        if model is None:
            # Fallback: score against global federated baseline
            if not self._global_baseline:
                return False
            z_scores = []
            for key, val in sample.items():
                try:
                    fval = float(val)
                except (TypeError, ValueError):
                    continue
                if key in self._global_baseline:
                    mean, std = self._global_baseline[key]
                    z_scores.append(_z_score(fval, mean, std))
            return bool(z_scores) and any(z >= 2.5 for z in z_scores)
        is_anomalous, _ = model.score(sample)
        return is_anomalous

    def anomaly_detail(
        self,
        model_id: str,
        sample: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return full z-score breakdown for each feature in *sample*."""
        model = self._models.get(model_id)
        if model is None:
            return {"error": "model_id not found", "model_id": model_id}
        is_anomalous, z_scores = model.score(sample)
        return {
            "model_id": model_id,
            "anomalous": is_anomalous,
            "threshold_z": model.threshold_z,
            "z_scores": z_scores,
            "top_feature": max(z_scores, key=z_scores.__getitem__) if z_scores else None,
        }

    # ------------------------------------------------------------------
    # Reinforcement learning
    # ------------------------------------------------------------------

    def reinforcement_learning(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Select the best response action for the given threat *state*.

        Uses an ε-greedy Q-table. The Q-table is updated via
        :meth:`record_outcome` after the operator acts.

        Args:
            state: Dict with keys severity, confidence, is_kev, host_risk.

        Returns:
            Dict with keys action, q_values, epsilon.
        """
        action = self._qtable.select_action(state)
        q_vals = self._qtable.q_values(state)
        return {
            "action": action,
            "q_values": {k: round(v, 4) for k, v in q_vals.items()},
            "epsilon": self._qtable.epsilon,
            "state_features": {
                "severity": state.get("severity", "medium"),
                "confidence": float(state.get("confidence", 0.5)),
                "is_kev": bool(state.get("is_kev", False)),
                "host_risk": float(state.get("host_risk", 0.5)),
            },
        }

    def record_outcome(
        self,
        state: Dict[str, Any],
        action: str,
        reward: float,
        next_state: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Feed an outcome back into the Q-table so it learns from history.

        Args:
            state: The state dict that was passed to reinforcement_learning.
            action: The action that was taken (observe/recommend/auto).
            reward: Positive for a true-positive response, negative for FP.
            next_state: State after the action (defaults to same state).
        """
        if next_state is None:
            next_state = state
        if action not in ACTIONS:
            raise ValueError(f"action must be one of {ACTIONS}")
        self._qtable.update(state, action, reward, next_state)

    # ------------------------------------------------------------------
    # Federated learning
    # ------------------------------------------------------------------

    def federated_learning(
        self,
        client_data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Federated averaging of per-agent baselines.

        Each element in *client_data* is a dict of feature statistics from one
        fleet agent. Expected keys per feature:  ``{feature}_mean`` and
        ``{feature}_std`` (and optionally ``{feature}_count``).

        Raw observations are never required — only the summary statistics are
        aggregated, keeping the protocol privacy-preserving.

        Returns:
            Dict with keys round, clients, global_baseline, delta.
        """
        if not client_data:
            return {"round": self._fed_round, "clients": 0,
                    "global_baseline": {}, "delta": {}}

        self._fed_round += 1

        # Collect per-feature weighted means and stds
        feature_means: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        feature_stds: Dict[str, List[Tuple[float, int]]] = defaultdict(list)

        for client in client_data:
            count = int(client.get("sample_count", 1))
            for key, val in client.items():
                if key == "sample_count":
                    continue
                try:
                    fval = float(val)
                except (TypeError, ValueError):
                    continue
                if key.endswith("_mean"):
                    feat = key[:-5]
                    feature_means[feat].append((fval, count))
                elif key.endswith("_std"):
                    feat = key[:-4]
                    feature_stds[feat].append((fval, count))

        # Federated averaging: weighted mean of means
        new_baseline: Dict[str, Tuple[float, float]] = {}
        for feat in feature_means:
            pairs = feature_means[feat]
            total = sum(c for _, c in pairs)
            if total == 0:
                continue
            agg_mean = sum(m * c for m, c in pairs) / total
            # Pool standard deviations (approximate)
            std_pairs = feature_stds.get(feat, [])
            if std_pairs:
                agg_std = math.sqrt(sum((s ** 2) * c for s, c in std_pairs) / total)
            else:
                agg_std = 0.0
            new_baseline[feat] = (round(agg_mean, 6), round(agg_std, 6))

        # Compute delta vs previous global baseline
        delta: Dict[str, float] = {}
        for feat, (new_m, _) in new_baseline.items():
            if feat in self._global_baseline:
                old_m, _ = self._global_baseline[feat]
                delta[feat] = round(abs(new_m - old_m), 6)

        self._global_baseline = new_baseline

        return {
            "round": self._fed_round,
            "clients": len(client_data),
            "global_baseline": {
                feat: {"mean": m, "std": s}
                for feat, (m, s) in new_baseline.items()
            },
            "delta": delta,
            "features_aggregated": len(new_baseline),
        }
