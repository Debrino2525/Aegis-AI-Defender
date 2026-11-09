"""Common Event Format (CEF) log parser."""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from aegis.ingest.base import BaseIngest, TelemetryEvent

logger = logging.getLogger(__name__)


class CEFParser(BaseIngest):
    """Parser for CEF (Common Event Format) logs."""

    CEF_PATTERN = re.compile(
        r'CEF:(?P<version>\d+)\|(?P<device_vendor>[^|]+)\|(?P<device_product>[^|]+)\|(?P<device_version>[^|]*)\|(?P<signature>[^|]+)\|(?P<name>[^|]+)\|(?P<severity>[^|]+)\|(?P<extension>.*)'
    )

    def connect(self) -> bool:
        return True

    def disconnect(self) -> None:
        pass

    def ingest(self, raw_log: str) -> Optional[TelemetryEvent]:
        """Parse a CEF log line.

        Args:
            raw_log: Raw CEF log string.

        Returns:
            TelemetryEvent object or None if parsing fails.
        """
        try:
            match = self.CEF_PATTERN.match(raw_log)
            if not match:
                return None

            groups = match.groupdict()
            extension = groups["extension"]

            # Parse key=value pairs from extension
            extension_data = {}
            if extension:
                for pair in extension.split():
                    if "=" in pair:
                        key, value = pair.split("=", 1)
                        extension_data[key] = value

            return TelemetryEvent(
                source="cef",
                event_type=groups["signature"],
                timestamp=self._now(),
                data={
                    "version": groups["version"],
                    "device_vendor": groups["device_vendor"],
                    "device_product": groups["device_product"],
                    "device_version": groups["device_version"],
                    "signature": groups["signature"],
                    "name": groups["name"],
                    "severity": groups["severity"],
                    "extension": extension_data,
                },
                raw=raw_log,
            )
        except Exception as e:
            logger.error(f"Failed to parse CEF log: {e}")
            return None

    def _now(self) -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
