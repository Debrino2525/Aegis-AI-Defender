"""SIEM integration adapters.

Supports:
- Splunk (HTTP Event Collector, REST API)
- Microsoft Sentinel (Azure Log Analytics)
- Elastic Security (Elasticsearch API)
"""

from __future__ import annotations

from aegis.integrations.siem.splunk import SplunkAdapter
from aegis.integrations.siem.sentinel import SentinelAdapter
from aegis.integrations.siem.elastic import ElasticAdapter

__all__ = [
    "SplunkAdapter",
    "SentinelAdapter",
    "ElasticAdapter",
]
