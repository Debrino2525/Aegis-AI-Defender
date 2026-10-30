"""HTTP routes for auditable host response."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from aegis.response.engine import ResponseEngine, ResponseError, get_response_engine
from aegis.response.rules import RESPONSE_RULES

router = APIRouter()

_get_context: Optional[Callable[[], Dict[str, Any]]] = None


def bind_context(getter: Callable[[], Dict[str, Any]]) -> None:
    global _get_context
    _get_context = getter


def _engine() -> ResponseEngine:
    return get_response_engine()


def _context() -> Dict[str, Any]:
    if _get_context is None:
        return {"hosts": [], "console_ips": [], "incident": None, "page_isolate": None}
    return _get_context()


def _http(exc: ResponseError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.message)


class SitePolicyRequest(BaseModel):
    site_mode: str
    auto_allowed: Optional[bool] = None
    confirm_auto: bool = False


class AssetModeRequest(BaseModel):
    mode: str


class PreviewRequest(BaseModel):
    incident_id: Optional[str] = None
    action: str
    target: str
    agent_id: Optional[str] = None
    incident: Optional[Dict[str, Any]] = None


class ConfirmRequest(BaseModel):
    action_id: str
    confirm: bool = Field(default=True)


class RollbackRequest(BaseModel):
    action_id: str
    confirm: bool = Field(default=True)


@router.get("/api/response/policy")
async def get_policy():
    return _engine().site_policy()


@router.post("/api/response/policy")
async def set_policy(body: SitePolicyRequest):
    try:
        return _engine().set_site_policy(
            site_mode=body.site_mode,
            auto_allowed=body.auto_allowed,
            confirm_auto=body.confirm_auto,
        )
    except ResponseError as exc:
        raise _http(exc) from exc


@router.get("/api/response/rules")
async def list_rules():
    return {"rules": _engine().list_rules()}


@router.get("/api/response/assets")
async def list_assets():
    ctx = _context()
    engine = _engine()
    site = engine.site_policy()
    hosts: List[Dict[str, Any]] = list(ctx.get("hosts") or [])
    rows = []
    seen = set()
    for host in hosts:
        agent_id = host.get("agent_id")
        if not agent_id or agent_id in seen:
            continue
        seen.add(agent_id)
        rows.append({
            "asset_id": agent_id,
            "hostname": host.get("hostname") or "",
            "status": host.get("status"),
            "mode": engine.asset_mode(agent_id),
            "effective_mode": engine.effective_asset_mode(agent_id),
        })
    rows.append({
        "asset_id": "console",
        "hostname": "this console",
        "status": "local",
        "mode": engine.asset_mode("console"),
        "effective_mode": engine.effective_asset_mode("console"),
    })
    return {"site": site, "assets": rows}


@router.post("/api/response/assets/{asset_id}")
async def set_asset_mode(asset_id: str, body: AssetModeRequest):
    try:
        return _engine().set_asset_mode(asset_id, body.mode)
    except ResponseError as exc:
        raise _http(exc) from exc


@router.get("/api/response/actions")
async def list_actions(
    incident_id: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    return {"actions": _engine().list_actions(incident_id=incident_id, asset_id=asset_id, limit=limit)}


@router.get("/api/response/actions/{action_id}")
async def get_action(action_id: str):
    record = _engine().get_action(action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Unknown action_id")
    return record


@router.get("/api/response/actions/{action_id}/audit")
async def get_action_audit(action_id: str):
    try:
        return _engine().verify_action_audit(action_id)
    except ResponseError as exc:
        raise _http(exc) from exc


@router.post("/api/response/preview")
async def preview_action(body: PreviewRequest):
    ctx = _context()
    incident = body.incident
    if body.incident_id:
        lookup = ctx.get("get_incident")
        if callable(lookup):
            found = lookup(body.incident_id)
            if found:
                incident = found
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        return _engine().preview(
            incident,
            body.action,
            body.target,
            actor="operator",
            agent_id=body.agent_id,
            hosts=ctx.get("hosts") or [],
            console_ips=ctx.get("console_ips") or [],
        )
    except ResponseError as exc:
        raise _http(exc) from exc


@router.post("/api/response/confirm")
async def confirm_action(body: ConfirmRequest):
    try:
        record = _engine().confirm(body.action_id, actor="operator", confirm=body.confirm)
    except ResponseError as exc:
        raise _http(exc) from exc
    pager = _context().get("page_isolate")
    if callable(pager):
        record = await pager(record)
    return record


@router.post("/api/response/rollback")
async def rollback_action(body: RollbackRequest):
    try:
        return _engine().rollback(body.action_id, actor="operator", confirm=body.confirm)
    except ResponseError as exc:
        raise _http(exc) from exc


# Imported so tests can assert the rule catalog is served, not duplicated.
RULE_COUNT = len(RESPONSE_RULES)
