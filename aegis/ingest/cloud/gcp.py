"""GCP Cloud Audit Logs ingestion."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from aegis.ingest.base import BaseIngest, TelemetryEvent

logger = logging.getLogger(__name__)


class GCPIngest(BaseIngest):
    def connect(self) -> bool:
        try:
            credentials = self.config.get("credentials")
            project_id = self.config.get("project_id")
            if credentials and project_id:
                self._connected = True
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to GCP: {e}")
            return False

    def disconnect(self) -> None:
        self._connected = False

    def ingest(self, start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[TelemetryEvent]:
        if not self.is_connected():
            return []
        return []
