"""HTTP routes for the device investigation object."""

from __future__ import annotations

from typing import Callable, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from aegis.investigate.device import (
    DeviceSources,
    build_investigation,
    investigation_id,
    list_investigations,
)
from aegis.monitor.remediation import preview_contain_action

router = APIRouter()

_get_sources: Optional[Callable[[], DeviceSources]] = None


def bind_sources(getter: Callable[[], DeviceSources]) -> None:
    global _get_sources
    _get_sources = getter


def _sources() -> DeviceSources:
    if _get_sources is None:
        raise HTTPException(status_code=503, detail="Investigation sources are not bound")
    return _get_sources()


class ContainPreviewRequest(BaseModel):
    action: str
    target: str
    dry_run: bool = Field(default=True)


@router.get("/api/investigations")
async def list_or_get_device_investigation(
    host: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    id: Optional[str] = Query(None, alias="id"),
):
    if host or ip or id:
        key = (id or "").strip() or (investigation_id("host", host) if host else investigation_id("ip", ip or ""))
        body = build_investigation(_sources(), key)
        if not body:
            raise HTTPException(status_code=404, detail="No enrolled host or source IP matches that key")
        return body
    return list_investigations(_sources())


@router.get("/api/investigations/{key:path}")
async def get_device_investigation(key: str):
    if key.endswith("/contain"):
        raise HTTPException(status_code=405, detail="Use POST for contain dry-run")
    body = build_investigation(_sources(), key)
    if not body:
        raise HTTPException(status_code=404, detail="No enrolled host or source IP matches that key")
    return body


@router.post("/api/investigations/{key:path}/contain")
async def preview_device_contain(key: str, body: ContainPreviewRequest):
    if body.dry_run is False:
        raise HTTPException(
            status_code=400,
            detail="Investigation contain is dry-run only. Execute from an incident action.",
        )
    investigation = build_investigation(_sources(), key)
    if not investigation:
        raise HTTPException(status_code=404, detail="No enrolled host or source IP matches that key")
    sockets = [
        item["sample"]
        for item in investigation.get("timeline") or []
        if item.get("kind") == "socket" and isinstance(item.get("sample"), dict)
    ]
    preview = preview_contain_action(body.action, body.target, sockets=sockets)
    matching = [
        action for action in investigation["contain"]["actions"]
        if action.get("action") == body.action and str(action.get("target") or "") == body.target
    ]
    if matching:
        preview["evidence_sample_id"] = matching[0].get("evidence_sample_id")
        preview["evidence"] = matching[0].get("evidence")
    preview["investigation_id"] = investigation["id"]
    preview["dry_run"] = True
    preview["mutates"] = False
    return preview
