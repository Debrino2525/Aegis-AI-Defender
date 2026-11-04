"""Google Workspace email telemetry ingestion."""

from __future__ import annotations

import logging
from aegis.ingest.base import BaseIngest, TelemetryEvent

logger = logging.getLogger(__name__)


class GoogleWorkspaceIngest(BaseIngest):
    def connect(self) -> bool:
        try:
            credentials = self.config.get("credentials")
            domain = self.config.get("domain")
            if credentials and domain:
                self._connected = True
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Google Workspace: {e}")
            return False

    def disconnect(self) -> None:
        self._connected = False

    def ingest(self, start_time=None, end_time=None):
        if not self.is_connected():
            return []
        return []
