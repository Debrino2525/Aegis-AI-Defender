"""Microsoft 365 email telemetry ingestion."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aegis.ingest.base import BaseIngest, TelemetryEvent

logger = logging.getLogger(__name__)


class Office365Ingest(BaseIngest):
    def connect(self) -> bool:
        try:
            client_id = self.config.get("client_id")
            client_secret = self.config.get("client_secret")
            tenant_id = self.config.get("tenant_id")
            if all([client_id, client_secret, tenant_id]):
                self._connected = True
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Office 365: {e}")
            return False

    def disconnect(self) -> None:
        self._connected = False

    def ingest(self, start_time: Optional[str] = None, end_time: Optional[str] = None) -> List[TelemetryEvent]:
        if not self.is_connected():
            return []
        return []
