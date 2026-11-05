"""JSON log parser."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from aegis.ingest.base import BaseIngest, TelemetryEvent

logger = logging.getLogger(__name__)


class JSONLogParser(BaseIngest):
    """Parser for JSON formatted logs."""

    def connect(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def ingest(self, raw_log: str) -> Optional[TelemetryEvent]:
        """Parse a JSON log line."""
        try:
            data = json.loads(raw_log)
            return TelemetryEvent(
                source="json",
                event_type=data.get("event_type", "unknown"),
                timestamp=data.get("timestamp") or self._now(),
                data=data,
                raw=raw_log,
            )
        except Exception as e:
            logger.error(f"Failed to parse JSON log: {e}")
            return None

    def _now(self) -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
