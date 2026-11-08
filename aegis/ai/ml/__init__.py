"""Machine learning modules for Aegis AI Defender."""

from aegis.ai.ml.isolation_forest import IsolationForestAnomalyDetector
from aegis.ai.ml.semantic_search import SemanticThreatSearch, DEFAULT_KNOWLEDGE_BASE

__all__ = [
    "IsolationForestAnomalyDetector",
    "SemanticThreatSearch",
    "DEFAULT_KNOWLEDGE_BASE",
]
