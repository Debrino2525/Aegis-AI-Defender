"""Microsoft 365 email telemetry ingestion."""

from __future__ import annotations

from aegis.ingest.base import BaseIngest, TelemetryEvent

class Office365Ingest(BaseIngest):
    def connect(self) -> bool:
        return bool(self.config.get("client_id"))
    def disconnect(self) -> None:
        pass
    def ingest(self, **kwargs):
        return []
