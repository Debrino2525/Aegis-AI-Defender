"""Firewall integration adapters.

Supports:
- Palo Alto Networks (Panorama/Firewall)
- Cisco Firepower
- Fortinet FortiGate
"""

from __future__ import annotations

from aegis.integrations.firewall.palo_alto import PaloAltoAdapter
from aegis.integrations.firewall.cisco import CiscoAdapter
from aegis.integrations.firewall.fortinet import FortinetAdapter

__all__ = [
    "PaloAltoAdapter",
    "CiscoAdapter",
    "FortinetAdapter",
]
