"""Visibility API routes."""

from fastapi import APIRouter
from aegis.visibility.fingerprinting import DeviceFingerprinter
from aegis.visibility.topology import NetworkTopology
from aegis.visibility.assets.servicenow import ServiceNowCMDB
from aegis.visibility.assets.lansweeper import Lansweeper

router = APIRouter()
fingerprinter = DeviceFingerprinter()
topology = NetworkTopology()

@router.get("/api/visibility/fingerprint/mac/{mac}")
async def fingerprint_mac(mac: str):
    return fingerprinter.fingerprint_from_mac(mac)

@router.get("/api/visibility/topology")
async def get_topology():
    return topology.get_topology()

@router.post("/api/visibility/assets/servicenow/connect")
async def connect_servicenow(instance_url: str, username: str, password: str):
    cmdb = ServiceNowCMDB(instance_url, username, password)
    return {"connected": cmdb.connect()}

@router.post("/api/visibility/assets/lansweeper/connect")
async def connect_lansweeper(api_url: str, api_key: str):
    ls = Lansweeper(api_url, api_key)
    return {"connected": ls.connect()}
