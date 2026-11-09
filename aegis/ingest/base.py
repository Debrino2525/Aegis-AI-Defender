"""Base class for telemetry ingestion adapters."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TelemetryEvent:
    """A single telemetry event."""
    source: str
    event_type: str
    timestamp: str
    data: Dict[str, Any]
    raw: Optional[str] = None


class BaseIngest(ABC):
    """Base class for telemetry ingestion adapters."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._connected = False

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the telemetry source."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the telemetry source."""
        pass

    @abstractmethod
    def ingest(self, **kwargs: Any) -> List[TelemetryEvent]:
        """Ingest telemetry events.

        Returns:
            List of TelemetryEvent objects.
        """
        pass

    def is_connected(self) -> bool:
        """Check if adapter is connected."""
        return self._connected

    def _now(self) -> str:
        """Get current UTC timestamp as ISO string."""
        return datetime.now(timezone.utc).isoformat()
