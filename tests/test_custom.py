"""Tests for customization module."""

from aegis.custom.models import CustomModelManager
from aegis.custom.risk import BusinessRiskEngine
from aegis.custom.stix import STIXManager

def test_custom_models():
    mgr = CustomModelManager()
    model_id = mgr.create_model("test", "pattern", "high")
    assert model_id is not None
    models = mgr.get_models()
    assert len(models) == 1

def test_business_risk():
    engine = BusinessRiskEngine()
    engine.add_vip_asset("asset1", "high")
    score = engine.calculate_risk("asset1", 5.0)
    assert score == 7.5

def test_stix_manager():
    mgr = STIXManager()
    feed_id = mgr.add_stix_feed("http://example.com/stix")
    assert feed_id is not None
