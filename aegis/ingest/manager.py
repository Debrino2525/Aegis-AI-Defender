"""Telemetry ingestion manager."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aegis.ingest.logs.cef import CEFParser
from aegis.ingest.logs.leef import LEEFParser
from aegis.ingest.logs.jsonl import JSONLogParser


class TelemetryManager:
    """Central manager for telemetry ingestion."""

    def __init__(self):
        self.parsers = {
            "cef": CEFParser({}),
            "leef": LEEFParser({}),
            "json": JSONLogParser({}),
        }

    def parse_log(self, log_format: str, raw_log: str) -> Optional[Dict[str, Any]]:
        """Parse a log line using the specified format.

        Args:
            log_format: Format type (cef, leef, json).
            raw_log: Raw log string.

        Returns:
            Parsed event data or None.
        """
        parser = self.parsers.get(log_format.lower())
        if not parser:
            return None

        event = parser.ingest(raw_log)
        if event:
            return {
                "source": event.source,
                "event_type": event.event_type,
                "timestamp": event.timestamp,
                "data": event.data,
                "raw": event.raw,
            }
        return None


# Global instance
_telemetry_manager: Optional[TelemetryManager] = None


def get_telemetry_manager() -> TelemetryManager:
    """Get the global telemetry manager instance."""
    global _telemetry_manager
    if _telemetry_manager is None:
        _telemetry_manager = TelemetryManager()
    return _telemetry_manager
