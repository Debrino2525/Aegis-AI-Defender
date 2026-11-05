"""MQTT protocol ingestion."""
from aegis.ingest.base import BaseIngest, TelemetryEvent
class MQTTIngest(BaseIngest):
    def connect(self):
        self._connected = bool(self.config.get("broker"))
        return self._connected
    def disconnect(self):
        self._connected = False
    def ingest(self, **kwargs):
        return []
