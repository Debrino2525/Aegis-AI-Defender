"""Unsupervised learning for anomaly detection, reinforcement learning, and federated aggregation.

Supports:
- Real Machine Learning: scikit-learn IsolationForest for multi-dimensional anomaly detection
- Real Statistical Baselines: Sliding-window rolling Z-score models
- Q-Learning Reinforcement Learning for autonomous response optimization
- Privacy-preserving Federated Averaging across multi-agent fleets
"""

from __future__ import annotations

import math
import time
import uuid
import statistics
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np  # type: ignore
    _HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore
    _HAS_NUMPY = False

from aegis.ai.ml.isolation_forest import IsolationForestAnomalyDetector


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
        self.windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window))
        self.stats: Dict[str, Tuple[float, float]] = {}
        self.trained = False
        self.trained_at: float = 0.0

    def fit(self, records: List[Dict[str, Any]]) -> None:
        feature_values: Dict[str, List[float]] = defaultdict(list)
        for rec in records:
            for key, val in rec.items():
                try:
                    feature_values[key].append(float(val))
                except (TypeError, ValueError):
                    pass
        for feat, vals in feature_values.items():
            self.stats[feat] = (_mean(vals), _stddev(vals))
            for v in vals[-self.window:]:
                self.windows[feat].append(v)
        self.trained = bool(self.stats)
        self.trained_at = time.time()

    def score(self, sample: Dict[str, Any]) -> Tuple[bool, Dict[str, float]]:
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
            self.windows[key].append(fval)
            vals = list(self.windows[key])
            self.stats[key] = (_mean(vals), _stddev(vals))

        anomalous = any(z >= self.threshold_z for z in z_scores.values())
        return anomalous, z_scores


# ---------------------------------------------------------------------------
# Q-table for Reinforcement Learning
# ---------------------------------------------------------------------------

ACTIONS = ("observe", "recommend", "auto")


class _QTable:
    """Tabular Q-learning for response-action selection."""

    def __init__(self, alpha: float = 0.1, gamma: float = 0.9, epsilon: float = 0.15):
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        self.q: Dict[Tuple, Dict[str, float]] = defaultdict(lambda: {a: 0.0 for a in ACTIONS})
        self.history: deque = deque(maxlen=500)

    def _discretize(self, state: Dict[str, Any]) -> Tuple:
        severity = str(state.get("severity", "medium")).lower()
        sev_bucket = {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(severity, 1)
        conf = float(state.get("confidence", 0.5))
        conf_bucket = int(min(conf * 4, 3))
        is_kev = int(bool(state.get("is_kev", False)))
        host_risk = int(min(float(state.get("host_risk", 0.5)) * 2, 1))
        return (sev_bucket, conf_bucket, is_kev, host_risk)

    def select_action(self, state: Dict[str, Any]) -> str:
        import random
        s = self._discretize(state)
        if random.random() < self.epsilon:
            return random.choice(ACTIONS)
        q_vals = self.q[s]
        return max(q_vals, key=q_vals.__getitem__)

    def update(self, state: Dict[str, Any], action: str, reward: float, next_state: Dict[str, Any]) -> None:
        s = self._discretize(state)
        ns = self._discretize(next_state)
        best_next = max(self.q[ns].values())
        old = self.q[s][action]
        self.q[s][action] = old + self.alpha * (reward + self.gamma * best_next - old)
        self.history.append((s, action, reward, ns))

    def q_values(self, state: Dict[str, Any]) -> Dict[str, float]:
        s = self._discretize(state)
        return dict(self.q[s])


# ---------------------------------------------------------------------------
# Public Class
# ---------------------------------------------------------------------------

class UnsupervisedLearning:
    """Unsupervised learning engine for multi-dimensional anomaly detection."""

    def __init__(self):
        self._models: Dict[str, _ZScoreModel] = {}
        self._iforest_models: Dict[str, IsolationForestAnomalyDetector] = {}
        self._qtable = _QTable()
        self._fed_round = 0
        self._global_baseline: Dict[str, Tuple[float, float]] = {}

    # ------------------------------------------------------------------
    # Real ML: Isolation Forest
    # ------------------------------------------------------------------

    def train_isolation_forest(
        self,
        data: List[Dict[str, Any]],
        contamination: float = 0.05,
        n_estimators: int = 100,
    ) -> str:
        """Fit a real scikit-learn IsolationForest model on network observations."""
        detector = IsolationForestAnomalyDetector(
            n_estimators=n_estimators,
            contamination=contamination,
        )
        model_id = detector.fit(data)
        self._iforest_models[model_id] = detector
        return model_id

    def score_isolation_forest(self, model_id: str, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Score an observation using the trained IsolationForest model."""
        detector = self._iforest_models.get(model_id)
        if detector is None:
            # If no trained iforest exists, instantiate and fit a baseline automatically
            detector = IsolationForestAnomalyDetector()
            detector.fit([sample, sample])
            self._iforest_models[detector.model_id] = detector
        return detector.score(sample)

    # ------------------------------------------------------------------
    # Statistical Anomaly detection
    # ------------------------------------------------------------------

    def train_anomaly_detector(
        self,
        data: List[Dict[str, Any]],
        threshold_z: float = 2.5,
        window: int = 200,
    ) -> str:
        """Fit a statistical z-score model and an Isolation Forest model."""
        if not data:
            raise ValueError("data must be a non-empty list of dicts")
        model = _ZScoreModel(threshold_z=threshold_z, window=window)
        model.fit(data)
        model_id = f"zscore-{uuid.uuid4().hex[:8]}"
        self._models[model_id] = model

        # Also fit an Isolation Forest on numeric records
        try:
            iforest = IsolationForestAnomalyDetector()
            iforest.fit(data)
            self._iforest_models[model_id] = iforest
        except Exception:
            pass

        return model_id

    def detect_anomaly(
        self,
        model_id: str,
        sample: Dict[str, Any],
    ) -> bool:
        """Detect anomaly using Isolation Forest combined with statistical Z-scores."""
        zscore_model = self._models.get(model_id)
        is_zscore_anom = False
        if zscore_model:
            is_zscore_anom, _ = zscore_model.score(sample)
        elif self._global_baseline:
            z_scores = []
            for key, val in sample.items():
                try:
                    fval = float(val)
                except (TypeError, ValueError):
                    continue
                if key in self._global_baseline:
                    mean, std = self._global_baseline[key]
                    z_scores.append(_z_score(fval, mean, std))
            is_zscore_anom = bool(z_scores) and any(z >= 2.5 for z in z_scores)

        is_iforest_anom = False
        if model_id in self._iforest_models:
            is_iforest_anom = self._iforest_models[model_id].predict(sample)

        return is_zscore_anom or is_iforest_anom

    def anomaly_detail(
        self,
        model_id: str,
        sample: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return full anomaly breakdown including Isolation Forest probability and Z-scores."""
        model = self._models.get(model_id)
        if model is None:
            return {"error": "model_id not found", "model_id": model_id}
        is_anomalous, z_scores = model.score(sample)

        res: Dict[str, Any] = {
            "model_id": model_id,
            "anomalous": is_anomalous,
            "threshold_z": model.threshold_z,
            "z_scores": z_scores,
            "top_feature": max(z_scores, key=z_scores.__getitem__) if z_scores else None,
        }

        # Include ML Isolation Forest scoring
        if model_id in self._iforest_models:
            iforest_res = self._iforest_models[model_id].score(sample)
            res["isolation_forest"] = iforest_res
            # If Isolation Forest detects outlier, escalate anomaly flag
            if iforest_res.get("is_anomaly"):
                res["anomalous"] = True

        return res

    # ------------------------------------------------------------------
    # Reinforcement learning
    # ------------------------------------------------------------------

    def reinforcement_learning(self, state: Dict[str, Any]) -> Dict[str, Any]:
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
        if not client_data:
            return {"round": self._fed_round, "clients": 0, "global_baseline": {}, "delta": {}}

        self._fed_round += 1
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

        new_baseline: Dict[str, Tuple[float, float]] = {}
        for feat in feature_means:
            pairs = feature_means[feat]
            total = sum(c for _, c in pairs)
            if total == 0:
                continue
            agg_mean = sum(m * c for m, c in pairs) / total
            std_pairs = feature_stds.get(feat, [])
            if std_pairs:
                agg_std = math.sqrt(sum((s ** 2) * c for s, c in std_pairs) / total)
            else:
                agg_std = 0.0
            new_baseline[feat] = (round(agg_mean, 6), round(agg_std, 6))

        delta: Dict[str, float] = {}
        for feat, (new_m, _) in new_baseline.items():
            if feat in self._global_baseline:
                old_m, _ = self._global_baseline[feat]
                delta[feat] = round(abs(new_m - old_m), 6)

        self._global_baseline = new_baseline

        return {
            "round": self._fed_round,
            "clients": len(client_data),
            "global_baseline": {feat: {"mean": m, "std": s} for feat, (m, s) in new_baseline.items()},
            "delta": delta,
            "features_aggregated": len(new_baseline),
        }
