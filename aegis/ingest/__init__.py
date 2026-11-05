"""Telemetry ingestion module.

Provides adapters for ingesting logs and telemetry from:
- Cloud platforms (AWS, Azure, GCP)
- Email systems (Microsoft 365, Google Workspace)
- OT/IoT protocols (Modbus, OPC UA, MQTT)
- Application logs (CEF, LEEF, JSON)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aegis.ingest.cloud.aws import AWSIngest
from aegis.ingest.cloud.azure import AzureIngest
from aegis.ingest.cloud.gcp import GCPIngest
from aegis.ingest.email.office365 import Office365Ingest
from aegis.ingest.email.google import GoogleWorkspaceIngest
from aegis.ingest.logs.cef import CEFParser
from aegis.ingest.logs.leef import LEEFParser
from aegis.ingest.logs.jsonl import JSONLogParser


__all__ = [
    "AWSIngest",
    "AzureIngest",
    "GCPIngest",
    "Office365Ingest",
    "GoogleWorkspaceIngest",
    "CEFParser",
    "LEEFParser",
    "JSONLogParser",
]
