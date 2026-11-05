"""Threat hunting API routes."""

from fastapi import APIRouter
from aegis.hunting.pcap import PCAPManager
from aegis.hunting.search import AdvancedSearch
from aegis.hunting.export import DataExporter

router = APIRouter()
pcap_mgr = PCAPManager()
search = AdvancedSearch()
exporter = DataExporter()

@router.post("/api/hunting/pcap/start")
async def start_pcap_capture(interface: str, duration: int = 60):
    return {"success": pcap_mgr.start_capture(interface, duration)}

@router.post("/api/hunting/pcap/stop")
async def stop_pcap_capture():
    return pcap_mgr.stop_capture()

@router.get("/api/hunting/search/alerts")
async def search_alerts(query: str, time_range: str = None):
    return search.search_alerts(query, time_range)

@router.get("/api/hunting/search/dns")
async def search_dns(domain: str, time_range: str = None):
    return search.search_dns(domain, time_range)

@router.get("/api/hunting/export/dns")
async def export_dns(time_range: str):
    return {"data": exporter.export_dns(time_range)}

@router.get("/api/hunting/export/http")
async def export_http(time_range: str):
    return {"data": exporter.export_http(time_range)}
