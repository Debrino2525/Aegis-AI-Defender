"""Customization API routes."""

from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel
from aegis.custom.models import CustomModelManager
from aegis.custom.risk import BusinessRiskEngine
from aegis.custom.stix import STIXManager

router = APIRouter()
model_mgr = CustomModelManager()
risk_engine = BusinessRiskEngine()
stix_mgr = STIXManager()


class CustomModelRequest(BaseModel):
    name: str
    pattern: str
    severity: str = "medium"


class RiskFrameworkRequest(BaseModel):
    framework: str


class VIPAssetRequest(BaseModel):
    asset_id: str
    criticality: str = "high"


class STIXFeedRequest(BaseModel):
    url: str
    api_key: Optional[str] = None


@router.post("/api/custom/models")
async def create_model(req: CustomModelRequest):
    model_id = model_mgr.create_model(req.name, req.pattern, req.severity)
    return {"model_id": model_id}

@router.get("/api/custom/models")
async def get_models():
    return model_mgr.get_models()

@router.post("/api/custom/risk/framework")
async def set_risk_framework(req: RiskFrameworkRequest):
    risk_engine.set_risk_framework(req.framework)
    return {"framework": req.framework}

@router.post("/api/custom/risk/vip")
async def add_vip_asset(req: VIPAssetRequest):
    return {"success": risk_engine.add_vip_asset(req.asset_id, req.criticality)}

@router.get("/api/custom/risk/vip")
async def get_vip_assets():
    return risk_engine.get_vip_assets()

@router.post("/api/custom/stix/feed")
async def add_stix_feed(req: STIXFeedRequest):
    feed_id = stix_mgr.add_stix_feed(req.url, req.api_key)
    return {"feed_id": feed_id}
