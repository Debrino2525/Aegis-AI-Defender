"""Real Machine Learning Anomaly Detection using Isolation Forest.

Uses scikit-learn IsolationForest to model multi-dimensional network socket
behavior without requiring labeled training sets.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest


class IsolationForestAnomalyDetector:
    """Ensemble Isolation Forest model for multi-dimensional anomaly detection."""

    def __init__(self, n_estimators: int = 100, contamination: str = "auto", random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.model_id: str = f"iforest-{uuid.uuid4().hex[:8]}"
        self.feature_names: List[str] = []
        self.is_fitted: bool = False
        self.sample_count: int = 0

    def _discover_features(self, data: List[Dict[str, Any]]) -> List[str]:
        keys = set()
        for row in data:
            for k, v in row.items():
                try:
                    float(v)
                    keys.add(k)
                except (ValueError, TypeError):
                    pass
        return sorted(keys)

    def _extract_vector(self, record: Dict[str, Any]) -> List[float]:
        vec = []
        for key in self.feature_names:
            val = record.get(key, 0.0)
            try:
                vec.append(float(val))
            except (ValueError, TypeError):
                vec.append(0.0)
        return vec

    def fit(self, data: List[Dict[str, Any]]) -> str:
        """Fit the Isolation Forest on network observation dictionaries."""
        if not data:
            raise ValueError("Training data must contain at least one observation.")

        self.feature_names = self._discover_features(data)
        if not self.feature_names:
            self.feature_names = ["connections", "bytes", "ports"]

        matrix = np.array([self._extract_vector(row) for row in data], dtype=np.float64)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(matrix)
        self.is_fitted = True
        self.sample_count = len(data)
        return self.model_id

    def predict(self, sample: Dict[str, Any]) -> bool:
        """Predict whether a sample is an anomaly (-1 means anomaly -> returns True)."""
        if not self.is_fitted or self.model is None:
            return False

        vec = np.array([self._extract_vector(sample)], dtype=np.float64)
        pred = self.model.predict(vec)
        return bool(pred[0] == -1)

    def score(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """Compute anomaly score and breakdown. Lower score = more anomalous."""
        if not self.is_fitted or self.model is None:
            return {"error": "Model not fitted yet", "is_anomaly": False}

        vec = np.array([self._extract_vector(sample)], dtype=np.float64)
        pred = self.model.predict(vec)[0]
        raw_score = float(self.model.decision_function(vec)[0])
        anomaly_prob = float(np.clip(0.5 - raw_score, 0.0, 1.0))

        return {
            "model_id": self.model_id,
            "algorithm": "IsolationForest",
            "is_anomaly": bool(pred == -1),
            "anomaly_probability": round(anomaly_prob, 4),
            "decision_score": round(raw_score, 4),
            "features_evaluated": dict(zip(self.feature_names, self._extract_vector(sample))),
            "training_samples": self.sample_count,
        }
