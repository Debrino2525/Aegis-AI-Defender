"""Tests for telemetry ingestion."""

import pytest
from aegis.ingest.logs.cef import CEFParser
from aegis.ingest.logs.leef import LEEFParser
from aegis.ingest.logs.jsonl import JSONLogParser


def test_cef_parser():
    parser = CEFParser({})
    cef_log = "CEF:0|Security|vendor|product|1.0|100|Access Denied|7|src=10.0.0.1 dst=10.0.0.2"
    event = parser.ingest(cef_log)
    assert event is not None
    assert event.data["device_vendor"] == "Security"
    assert event.data["signature"] == "100"


def test_leef_parser():
    parser = LEEFParser({})
    leef_log = "Security|product|1.0|100|Access Denied|7|src=10.0.0.1"
    event = parser.ingest(leef_log)
    assert event is not None
    assert event.data["device_vendor"] == "Security"


def test_json_parser():
    parser = JSONLogParser({})
    json_log = '{"event_type": "access", "timestamp": "2024-01-01T00:00:00Z", "user": "admin"}'
    event = parser.ingest(json_log)
    assert event is not None
    assert event.data["event_type"] == "access"
