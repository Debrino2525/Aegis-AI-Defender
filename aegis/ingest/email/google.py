"""Google Workspace email telemetry ingestion."""

from __future__ import annotations

from aegis.ingest.base import BaseIngest, TelemetryEvent

class GoogleWorkspaceIngest(BaseIngest):
    def connect(self) -> bool:
        return bool(self.config.get("service_account"))
    def disconnect(self) -> None:
        pass
    def ingest(self, **kwargs):
        return []
