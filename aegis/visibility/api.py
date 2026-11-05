"""Visibility API routes."""

from fastapi import APIRouter
from aegis.visibility.fingerprinting import DeviceFingerprinter
from aegis.visibility.topology import NetworkTopology

router = APIRouter()
fingerprinter = DeviceFingerprinter()
topology = NetworkTopology()

@router.get("/api/visibility/fingerprint/mac/{mac}")
async def fingerprint_mac(mac: str):
    return fingerprinter.fingerprint_from_mac(mac)

@router.get("/api/visibility/topology")
async def get_topology():
    return topology.get_topology()
