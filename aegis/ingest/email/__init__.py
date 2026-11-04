"""Email telemetry ingestion adapters."""

from __future__ import annotations

from aegis.ingest.email.office365 import Office365Ingest
from aegis.ingest.email.google import GoogleWorkspaceIngest

__all__ = ["Office365Ingest", "GoogleWorkspaceIngest"]
