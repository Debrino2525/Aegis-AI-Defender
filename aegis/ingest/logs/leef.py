"""Log Event Extended Format (LEEF) log parser."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from aegis.ingest.base import BaseIngest, TelemetryEvent

logger = logging.getLogger(__name__)


class LEEFParser(BaseIngest):
    """Parser for LEEF (Log Event Extended Format) logs."""

    def connect(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def ingest(self, raw_log: str) -> Optional[TelemetryEvent]:
        """Parse a LEEF log line."""
        try:
            parts = raw_log.split("|")
            if len(parts) < 6:
                return None

            return TelemetryEvent(
                source="leef",
                event_type=parts[4],
                timestamp=self._now(),
                data={
                    "device_vendor": parts[0],
                    "device_product": parts[1],
                    "device_version": parts[2],
                    "signature": parts[3],
                    "name": parts[4],
                    "severity": parts[5],
                },
                raw=raw_log,
            )
        except Exception as e:
            logger.error(f"Failed to parse LEEF log: {e}")
            return None

    def _now(self) -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
