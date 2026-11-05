"""Tests for advanced AI module."""

from aegis.ai.unsupervised import UnsupervisedLearning
from aegis.ai.predictive import PredictiveAnalytics
from aegis.ai.nlp import NaturalLanguageProcessing

def test_unsupervised_learning():
    model = UnsupervisedLearning()
    model_id = model.train_anomaly_detector([{"data": "test"}])
    assert model_id is not None
    result = model.detect_anomaly(model_id, {"data": "test"})
    assert isinstance(result, bool)

def test_predictive_analytics():
    model = PredictiveAnalytics()
    prediction = model.predict_next_attack({"id": 1})
    assert "predicted_step" in prediction

def test_nlp():
    nlp = NaturalLanguageProcessing()
    summary = nlp.summarize_incident({"id": 1})
    assert isinstance(summary, str)
