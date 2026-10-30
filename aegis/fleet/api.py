"""HTTP routes for host-agent enrollment and heartbeats."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from aegis.fleet.service import get_fleet_service
from aegis.fleet.tls import heartbeat_requires_client_cert, peer_cert_pem_from_request
from aegis.response.engine import get_response_engine

router = APIRouter()


class EnrollRequest(BaseModel):
    token: str
    hostname: str
    os_name: str = ""
    os_version: str = ""
    arch: str = ""
    agent_version: str = ""


class HeartbeatRequest(BaseModel):
    agent_id: str = ""
    timestamp: str
    nonce: str
    certificate_pem: str = ""
    signature_b64: str = ""
    telemetry: Optional[Dict[str, Any]] = None
    command_results: Optional[List[Dict[str, Any]]] = None


class MintTokenRequest(BaseModel):
    label: str = Field(default="", max_length=80)


class RevokeRequest(BaseModel):
    reason: str = Field(default="operator", max_length=80)


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
        result = service.heartbeat(
            agent_id=body.agent_id,
            timestamp=body.timestamp,
            nonce=body.nonce,
            certificate_pem=body.certificate_pem,
            signature_b64=body.signature_b64,
            telemetry=body.telemetry,
            remote_ip=_client_ip(request),
            peer_cert_pem=peer_cert_pem_from_request(request),
            require_tls_client_cert=heartbeat_requires_client_cert(),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    engine = get_response_engine()
    agent_id = result.get("agent_id") or body.agent_id
    if body.command_results:
        engine.ingest_command_results(agent_id, body.command_results)
    result["commands"] = engine.dequeue_commands(agent_id)
    return result


@router.get("/api/fleet/hosts")
async def list_fleet_hosts(include_all: bool = Query(False, alias="all")):
    payload = get_fleet_service().list_hosts(include_never_seen=include_all)
    engine = get_response_engine()
    for host in payload.get("hosts") or []:
        agent_id = host.get("agent_id") or ""
        host["response_mode"] = engine.asset_mode(agent_id)
        host["effective_response_mode"] = engine.effective_asset_mode(agent_id)
    return payload


@router.get("/api/fleet/status")
async def fleet_status():
    return get_fleet_service().status()


@router.post("/api/fleet/tokens")
async def mint_enrollment_token(body: MintTokenRequest = MintTokenRequest()):
    minted = get_fleet_service().mint_token(label=body.label)
    return minted


@router.post("/api/fleet/hosts/{agent_id}/revoke")
async def revoke_host(agent_id: str, body: RevokeRequest = RevokeRequest()):
    try:
        return get_fleet_service().revoke(agent_id, reason=body.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown agent_id") from exc


@router.post("/api/fleet/hosts/{agent_id}/reenroll")
async def reenroll_host(agent_id: str):
    try:
        return get_fleet_service().reenroll(agent_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown agent_id") from exc
