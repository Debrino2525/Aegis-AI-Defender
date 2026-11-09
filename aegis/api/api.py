"""API extensibility routes."""

from fastapi import APIRouter
from aegis.api.ingest import DataIngestionAPI
from aegis.api.output import AlertOutputAPI
from aegis.api.export import IncidentExportAPI

router = APIRouter()
ingest_api = DataIngestionAPI()
output_api = AlertOutputAPI()
export_api = IncidentExportAPI()

from pydantic import BaseModel
from typing import Any, Dict, List

class WebhookPayload(BaseModel):
    source: str
    data: Dict[str, Any]

class BulkUploadPayload(BaseModel):
    data_type: str
    data: List[Any]

class CallbackPayload(BaseModel):
    url: str
    auth_token: str

@router.post("/api/ext/ingest/webhook")
async def receive_webhook(payload: WebhookPayload):
    return {"success": ingest_api.receive_webhook(payload.source, payload.data)}

@router.post("/api/ext/ingest/bulk")
async def bulk_upload(payload: BulkUploadPayload):
    count = ingest_api.bulk_upload(payload.data_type, payload.data)
    return {"processed": count}

@router.post("/api/ext/output/callback")
async def register_callback(payload: CallbackPayload):
    callback_id = output_api.register_callback(payload.url, payload.auth_token)
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
