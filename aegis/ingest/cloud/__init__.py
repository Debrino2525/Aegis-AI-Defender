"""Cloud log ingestion adapters."""

from __future__ import annotations

from aegis.ingest.cloud.aws import AWSIngest
from aegis.ingest.cloud.azure import AzureIngest
from aegis.ingest.cloud.gcp import GCPIngest

__all__ = ["AWSIngest", "AzureIngest", "GCPIngest"]
