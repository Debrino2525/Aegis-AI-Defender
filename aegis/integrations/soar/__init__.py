"""SOAR integration adapters.

Supports:
- Cortex XSOAR (Palo Alto)
- Splunk SOAR
"""

from __future__ import annotations

from aegis.integrations.soar.cortex import CortexAdapter
from aegis.integrations.soar.splunk_soar import SplunkSoarAdapter

__all__ = [
    "CortexAdapter",
    "SplunkSoarAdapter",
]
