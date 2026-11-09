"""Integration adapters for external security systems.

This module provides adapters for integrating Aegis with:
- SIEM systems (Splunk, Microsoft Sentinel, Elastic Security)
- SOAR platforms (Cortex XSOAR, Splunk SOAR)
- Ticketing systems (ServiceNow, Jira)
- Firewalls (Palo Alto, Cisco, Fortinet)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aegis.integrations.base import BaseAdapter, IntegrationError, IntegrationStatus


__all__ = [
    "BaseAdapter",
    "IntegrationError",
    "IntegrationStatus",
]


def list_available_integrations() -> List[Dict[str, Any]]:
    """List all available integration types with their capabilities."""
    return [
        {
            "id": "splunk",
            "name": "Splunk",
            "type": "siem",
            "capabilities": ["alert_ingest", "alert_output", "search"],
            "auth_methods": ["token", "basic"],
        },
        {
            "id": "microsoft_sentinel",
            "name": "Microsoft Sentinel",
            "type": "siem",
            "capabilities": ["alert_output", "log_ingest"],
            "auth_methods": ["oauth2"],
        },
        {
            "id": "elastic_security",
            "name": "Elastic Security",
            "type": "siem",
            "capabilities": ["alert_output", "search"],
            "auth_methods": ["api_key", "basic"],
        },
        {
            "id": "cortex_xsoar",
            "name": "Cortex XSOAR",
            "type": "soar",
            "capabilities": ["incident_create", "playbook_trigger"],
            "auth_methods": ["api_key"],
        },
        {
            "id": "splunk_soar",
            "name": "Splunk SOAR",
            "type": "soar",
            "capabilities": ["incident_create", "playbook_trigger"],
            "auth_methods": ["api_key"],
        },
        {
            "id": "servicenow",
            "name": "ServiceNow",
            "type": "ticketing",
            "capabilities": ["incident_create", "incident_update"],
            "auth_methods": ["oauth2", "basic"],
        },
        {
            "id": "jira",
            "name": "Jira",
            "type": "ticketing",
            "capabilities": ["issue_create", "issue_update"],
            "auth_methods": ["api_token", "oauth"],
        },
        {
            "id": "palo_alto",
            "name": "Palo Alto Networks",
            "type": "firewall",
            "capabilities": ["ip_block", "ip_unblock", "url_filter"],
            "auth_methods": ["api_key"],
        },
        {
            "id": "cisco_firepower",
            "name": "Cisco Firepower",
            "type": "firewall",
            "capabilities": ["ip_block", "ip_unblock", "rule_create"],
            "auth_methods": ["api_key", "basic"],
        },
        {
            "id": "fortinet",
            "name": "Fortinet FortiGate",
            "type": "firewall",
            "capabilities": ["ip_block", "ip_unblock", "policy_create"],
            "auth_methods": ["api_token"],
        },
    ]
