"""HTTP routes for the unified asset catalog."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence

from fastapi import APIRouter

from aegis.assets.posture import attach_host_posture, unmatched_scans
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
