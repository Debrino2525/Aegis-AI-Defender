"""Application log ingestion adapters."""

from __future__ import annotations

from aegis.ingest.logs.cef import CEFParser
from aegis.ingest.logs.leef import LEEFParser
from aegis.ingest.logs.jsonl import JSONLogParser

__all__ = ["CEFParser", "LEEFParser", "JSONLogParser"]
