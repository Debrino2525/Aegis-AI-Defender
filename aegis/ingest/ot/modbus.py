"""Modbus protocol ingestion."""
from aegis.ingest.base import BaseIngest, TelemetryEvent
class ModbusIngest(BaseIngest):
    def connect(self): return True
    def disconnect(self): pass
    def ingest(self, **kwargs): return []
