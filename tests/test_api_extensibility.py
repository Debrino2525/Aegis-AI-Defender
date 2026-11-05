"""Tests for API extensibility module."""

from aegis.api.ingest import DataIngestionAPI
from aegis.api.output import AlertOutputAPI
from aegis.api.export import IncidentExportAPI

def test_data_ingestion():
    api = DataIngestionAPI()
    assert api.receive_webhook("test", {"data": "test"}) == True
    count = api.bulk_upload("alerts", [{"id": 1}, {"id": 2}])
    assert count == 2

def test_alert_output():
    api = AlertOutputAPI()
    callback_id = api.register_callback("http://example.com", "token")
    assert callback_id is not None
    assert api.push_alert({"id": 1}) == True

def test_incident_export():
    api = IncidentExportAPI()
    bundle = api.export_incident_bundle("inc1")
    assert bundle["incident_id"] == "inc1"
