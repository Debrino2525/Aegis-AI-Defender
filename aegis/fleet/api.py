"""HTTP routes for host-agent enrollment and heartbeats."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from aegis.fleet.service import get_fleet_service

router = APIRouter()


class EnrollRequest(BaseModel):
    token: str
    hostname: str
    os_name: str = ""
    os_version: str = ""
    arch: str = ""
    agent_version: str = ""


class HeartbeatRequest(BaseModel):
    agent_id: str
    timestamp: str
    nonce: str
    certificate_pem: str
    signature_b64: str
    telemetry: Optional[Dict[str, Any]] = None


class MintTokenRequest(BaseModel):
    label: str = Field(default="", max_length=80)


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return ""


@router.post("/api/fleet/enroll")
async def enroll_agent(body: EnrollRequest, request: Request):
    service = get_fleet_service()
    try:
        return service.enroll(
            token=body.token,
            hostname=body.hostname,
            os_name=body.os_name,
            os_version=body.os_version,
            arch=body.arch,
            agent_version=body.agent_version,
            remote_ip=_client_ip(request),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/api/fleet/heartbeat")
async def agent_heartbeat(body: HeartbeatRequest, request: Request):
    service = get_fleet_service()
    try:
        return service.heartbeat(
            agent_id=body.agent_id,
            timestamp=body.timestamp,
            nonce=body.nonce,
            certificate_pem=body.certificate_pem,
            signature_b64=body.signature_b64,
            telemetry=body.telemetry,
            remote_ip=_client_ip(request),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/fleet/hosts")
async def list_fleet_hosts():
    return get_fleet_service().list_hosts()


@router.get("/api/fleet/status")
async def fleet_status():
    return get_fleet_service().status()


@router.post("/api/fleet/tokens")
async def mint_enrollment_token(body: MintTokenRequest = MintTokenRequest()):
    minted = get_fleet_service().mint_token(label=body.label)
    return minted
