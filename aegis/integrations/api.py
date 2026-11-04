"""HTTP API routes for integration management."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from aegis.integrations.manager import get_integration_manager
from aegis.integrations.base import IntegrationError

router = APIRouter()


class IntegrationConfigRequest(BaseModel):
    """Request model for configuring an integration."""
    enabled: bool = False
    config: Dict[str, Any] = Field(default_factory=dict)


class AlertSendRequest(BaseModel):
    """Request model for sending an alert."""
    alert: Dict[str, Any]
    integration_ids: Optional[List[str]] = None


class IncidentSendRequest(BaseModel):
    """Request model for sending an incident."""
    incident: Dict[str, Any]
    integration_ids: Optional[List[str]] = None


class BlockIPRequest(BaseModel):
    """Request model for blocking an IP."""
    ip_address: str
    integration_ids: Optional[List[str]] = None
    rule_name: Optional[str] = None


class UnblockIPRequest(BaseModel):
    """Request model for unblocking an IP."""
    ip_address: str
    integration_ids: Optional[List[str]] = None
    rule_name: Optional[str] = None


@router.get("/api/integrations")
async def list_integrations():
    """List all available integrations with their status."""
    manager = get_integration_manager()
    return {"integrations": manager.list_integrations()}


@router.get("/api/integrations/{integration_id}")
async def get_integration(integration_id: str):
    """Get details for a specific integration."""
    manager = get_integration_manager()
    integration = manager.get_integration(integration_id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    return integration


@router.post("/api/integrations/{integration_id}/configure")
async def configure_integration(integration_id: str, body: IntegrationConfigRequest):
    """Configure an integration."""
    manager = get_integration_manager()
    try:
        config = manager.configure_integration(
            integration_id,
            {"enabled": body.enabled, **body.config},
        )
        return config
    except IntegrationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/integrations/{integration_id}/connect")
async def connect_integration(integration_id: str):
    """Connect to an integration."""
    manager = get_integration_manager()
    try:
        return manager.connect_integration(integration_id)
    except IntegrationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/integrations/{integration_id}/disconnect")
async def disconnect_integration(integration_id: str):
    """Disconnect from an integration."""
    manager = get_integration_manager()
    return manager.disconnect_integration(integration_id)


@router.post("/api/integrations/{integration_id}/test")
async def test_integration(integration_id: str):
    """Test connection to an integration."""
    manager = get_integration_manager()
    return manager.test_integration(integration_id)


@router.post("/api/integrations/alert")
async def send_alert(body: AlertSendRequest):
    """Send an alert to configured integrations."""
    manager = get_integration_manager()
    return manager.send_alert(body.alert, body.integration_ids)


@router.post("/api/integrations/incident")
async def send_incident(body: IncidentSendRequest):
    """Send an incident to configured integrations."""
    manager = get_integration_manager()
    return manager.send_incident(body.incident, body.integration_ids)


@router.post("/api/integrations/block-ip")
async def block_ip(body: BlockIPRequest):
    """Block an IP address on configured firewall integrations."""
    manager = get_integration_manager()
    return manager.block_ip(body.ip_address, body.integration_ids)


@router.post("/api/integrations/unblock-ip")
async def unblock_ip(body: UnblockIPRequest):
    """Unblock an IP address on configured firewall integrations."""
    manager = get_integration_manager()
    return manager.unblock_ip(body.ip_address, body.integration_ids)
