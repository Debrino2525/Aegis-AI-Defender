"""HTTP routes for the unified asset catalog."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from fastapi import APIRouter, HTTPException

from aegis.assets.posture import attach_host_posture, unmatched_scans
from aegis.assets.fingerprint import get_device_fingerprinter, DeviceFingerprint
from aegis.assets.inventory import get_asset_inventory, AssetStatus, AssetRiskLevel
from aegis.fleet.service import get_fleet_service
from aegis.response.engine import get_response_engine

router = APIRouter()

_get_scans: Optional[Callable[[], Sequence[Dict[str, Any]]]] = None


def bind_scans(getter: Callable[[], Sequence[Dict[str, Any]]]) -> None:
    global _get_scans
    _get_scans = getter


def live_scans() -> List[Dict[str, Any]]:
    if _get_scans is None:
        return []
    return list(_get_scans() or [])


def decorate_hosts(hosts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach response mode and Prevent posture. Same object Assets and fleet list share."""
    rows = list(hosts or [])
    engine = get_response_engine()
    for host in rows:
        agent_id = host.get("agent_id") or ""
        host["response_mode"] = engine.asset_mode(agent_id)
        host["effective_response_mode"] = engine.effective_asset_mode(agent_id)
    attach_host_posture(rows, live_scans())
    return rows


@router.get("/api/assets")
async def list_assets():
    hosts = get_fleet_service().list_hosts(include_never_seen=False).get("hosts") or []
    assets = decorate_hosts(hosts)
    return {
        "assets": assets,
        "unmatched_scans": unmatched_scans(assets, live_scans()),
    }


@router.get("/api/inventory")
async def list_inventory(
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
):
    """List assets from inventory with optional filters."""
    inventory = get_asset_inventory()

    status_filter = AssetStatus(status) if status else None
    risk_filter = AssetRiskLevel(risk_level) if risk_level else None

    assets = inventory.list_assets(status=status_filter, risk_level=risk_filter)
    return {
        "assets": [a.to_dict() for a in assets],
        "statistics": inventory.get_statistics(),
    }


@router.get("/api/inventory/{asset_id}")
async def get_inventory_asset(asset_id: str):
    """Get a specific asset from inventory."""
    inventory = get_asset_inventory()
    asset = inventory.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset.to_dict()


@router.get("/api/inventory/{asset_id}/fingerprint")
async def get_asset_fingerprint(asset_id: str):
    """Get fingerprint for a specific asset."""
    fingerprinter = get_device_fingerprinter()
    fp = fingerprinter.get_fingerprint(asset_id)
    if not fp:
        raise HTTPException(status_code=404, detail="Fingerprint not found")
    return fp.to_dict()


@router.post("/api/inventory/{asset_id}/status")
async def update_asset_status(asset_id: str, req: Dict[str, Any]):
    """Update asset status."""
    inventory = get_asset_inventory()
    asset = inventory.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    new_status = req.get("status")
    if not new_status:
        raise HTTPException(status_code=400, detail="Status required")

    try:
        status_enum = AssetStatus(new_status)
        asset.update_status(status_enum, source="api")
        inventory._save_inventory()
        return {"ok": True, "status": asset.status.value}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid status")


@router.post("/api/inventory/{asset_id}/tags")
async def update_asset_tags(asset_id: str, req: Dict[str, Any]):
    """Update asset tags."""
    inventory = get_asset_inventory()
    asset = inventory.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    action = req.get("action", "add")
    tags = req.get("tags", [])

    if action == "add":
        for tag in tags:
            asset.add_tag(tag)
    elif action == "remove":
        for tag in tags:
            asset.remove_tag(tag)
    else:
        raise HTTPException(status_code=400, detail="Invalid action")

    inventory._save_inventory()
    return {"ok": True, "tags": list(asset.tags)}


@router.post("/api/inventory/recalculate-risks")
async def recalculate_risks():
    """Recalculate risk levels for all assets."""
    inventory = get_asset_inventory()
    inventory.update_all_risks()
    return {"ok": True, "statistics": inventory.get_statistics()}


@router.get("/api/inventory/search")
async def search_inventory(q: str):
    """Search assets by hostname, tags, or notes."""
    inventory = get_asset_inventory()
    results = inventory.search_assets(q)
    return {
        "query": q,
        "results": [a.to_dict() for a in results],
        "count": len(results),
    }
