"""Modbus protocol ingestion."""
from aegis.ingest.base import BaseIngest, TelemetryEvent
class ModbusIngest(BaseIngest):
    def connect(self):
        self._connected = bool(self.config.get("host"))
        return self._connected
    def disconnect(self):
        self._connected = False
    def ingest(self, **kwargs):
        return []
