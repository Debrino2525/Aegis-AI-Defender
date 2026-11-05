"""Ticketing system integration adapters.

Supports:
- ServiceNow
- Jira
"""

from __future__ import annotations

from aegis.integrations.ticketing.servicenow import ServiceNowAdapter
from aegis.integrations.ticketing.jira import JiraAdapter

__all__ = [
    "ServiceNowAdapter",
    "JiraAdapter",
]
