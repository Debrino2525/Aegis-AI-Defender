"""Visibility API routes."""

from fastapi import APIRouter
from pydantic import BaseModel
from aegis.visibility.fingerprinting import DeviceFingerprinter
from aegis.visibility.topology import NetworkTopology
from aegis.visibility.assets.servicenow import ServiceNowCMDB
from aegis.visibility.assets.lansweeper import Lansweeper

router = APIRouter()
fingerprinter = DeviceFingerprinter()
topology = NetworkTopology()


class ServiceNowConnectRequest(BaseModel):
    instance_url: str
    username: str
    password: str


class LansweeperConnectRequest(BaseModel):
    api_url: str
    api_key: str


@router.get("/api/visibility/fingerprint/mac/{mac}")
async def fingerprint_mac(mac: str):
    return fingerprinter.fingerprint_from_mac(mac)

@router.get("/api/visibility/topology")
async def get_topology():
    return topology.get_topology()

@router.post("/api/visibility/assets/servicenow/connect")
async def connect_servicenow(req: ServiceNowConnectRequest):
    cmdb = ServiceNowCMDB(req.instance_url, req.username, req.password)
    return {"connected": cmdb.connect()}

@router.post("/api/visibility/assets/lansweeper/connect")
async def connect_lansweeper(req: LansweeperConnectRequest):
    ls = Lansweeper(req.api_url, req.api_key)
    return {"connected": ls.connect()}
