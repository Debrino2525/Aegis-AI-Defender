"""OPC UA protocol ingestion."""
from aegis.ingest.base import BaseIngest, TelemetryEvent
class OPCUAIngest(BaseIngest):
    def connect(self):
        self._connected = bool(self.config.get("endpoint"))
        return self._connected
    def disconnect(self):
        self._connected = False
    def ingest(self, **kwargs):
        return []
