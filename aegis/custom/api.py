"""Customization API routes."""

from fastapi import APIRouter
from aegis.custom.models import CustomModelManager
from aegis.custom.risk import BusinessRiskEngine
from aegis.custom.stix import STIXManager

router = APIRouter()
model_mgr = CustomModelManager()
risk_engine = BusinessRiskEngine()
stix_mgr = STIXManager()

@router.post("/api/custom/models")
async def create_model(name: str, pattern: str, severity: str = "medium"):
    model_id = model_mgr.create_model(name, pattern, severity)
    return {"model_id": model_id}

@router.get("/api/custom/models")
async def get_models():
    return model_mgr.get_models()

@router.post("/api/custom/risk/framework")
async def set_risk_framework(framework: str):
    risk_engine.set_risk_framework(framework)
    return {"framework": framework}

@router.post("/api/custom/risk/vip")
async def add_vip_asset(asset_id: str, criticality: str = "high"):
    return {"success": risk_engine.add_vip_asset(asset_id, criticality)}

@router.get("/api/custom/risk/vip")
async def get_vip_assets():
    return risk_engine.get_vip_assets()

@router.post("/api/custom/stix/feed")
async def add_stix_feed(url: str, api_key: str = None):
    feed_id = stix_mgr.add_stix_feed(url, api_key)
    return {"feed_id": feed_id}
