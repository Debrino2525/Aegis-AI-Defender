"""OT/IoT telemetry ingestion adapters."""

from __future__ import annotations

from aegis.ingest.ot.modbus import ModbusIngest
from aegis.ingest.ot.opcua import OPCUAIngest
from aegis.ingest.ot.mqtt import MQTTIngest

__all__ = ["ModbusIngest", "OPCUAIngest", "MQTTIngest"]
