"""API extensibility routes."""

from fastapi import APIRouter
from aegis.api.ingest import DataIngestionAPI
from aegis.api.output import AlertOutputAPI
from aegis.api.export import IncidentExportAPI

router = APIRouter()
ingest_api = DataIngestionAPI()
output_api = AlertOutputAPI()
export_api = IncidentExportAPI()

@router.post("/api/ext/ingest/webhook")
async def receive_webhook(source: str, data: dict):
    return {"success": ingest_api.receive_webhook(source, data)}

@router.post("/api/ext/ingest/bulk")
async def bulk_upload(data_type: str, data: list):
    count = ingest_api.bulk_upload(data_type, data)
    return {"processed": count}

@router.post("/api/ext/output/callback")
async def register_callback(url: str, auth_token: str):
    callback_id = output_api.register_callback(url, auth_token)
    return {"callback_id": callback_id}

@router.post("/api/ext/output/push")
async def push_alert(alert: dict):
    return {"success": output_api.push_alert(alert)}

@router.get("/api/ext/export/incident/{incident_id}")
async def export_incident(incident_id: str):
    return export_api.export_incident_bundle(incident_id)

@router.get("/api/ext/export/pcap/{incident_id}")
async def export_pcap(incident_id: str):
    return export_api.export_pcap(incident_id)
