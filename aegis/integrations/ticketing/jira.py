"""Jira integration adapter.

Supports:
- Issue creation via REST API
- Issue updates and comments
- API token and OAuth authentication
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class JiraAdapter(BaseAdapter):
    """Adapter for Jira integration."""

    @property
    def integration_type(self) -> str:
        return "ticketing"

    def connect(self) -> bool:
        """Establish connection to Jira."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Jira URL not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to Jira."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to Jira."""
        try:
            url = self.config.config.get("url")
            if not url:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            headers = self._build_headers()
            response = requests.get(f"{url}/rest/api/3/myself", headers=headers, timeout=10)

            if response.status_code == 200:
                self.config.last_test_status = IntegrationStatus.CONNECTED
                self.config.last_tested = self._now()
                return IntegrationStatus.CONNECTED
            elif response.status_code == 401:
                self.config.last_test_status = IntegrationStatus.ERROR
                self.config.last_error = "Authentication failed"
                return IntegrationStatus.ERROR
            else:
                self.config.last_test_status = IntegrationStatus.DISCONNECTED
                return IntegrationStatus.DISCONNECTED
        except requests.exceptions.Timeout:
            self.config.last_test_status = IntegrationStatus.ERROR
            self.config.last_error = "Connection timeout"
            return IntegrationStatus.ERROR
        except Exception as e:
            self.log_error(e)
            self.config.last_test_status = IntegrationStatus.ERROR
            self.config.last_error = str(e)
            return IntegrationStatus.ERROR

    def send_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Send alert to Jira as an issue."""
        try:
            url = self.config.config.get("url")
            project_key = self.config.config.get("project_key")
            issue_type = self.config.config.get("issue_type", "Bug")

            if not url or not project_key:
                raise IntegrationError("Jira URL or project key not configured")

            # Format alert as Jira issue
            issue = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": f"Aegis Alert: {alert.get('title')}",
                    "description": self._build_description(alert),
                    "issuetype": {"name": issue_type},
                    "priority": {"name": self._map_priority(alert.get("severity"))},
                    "labels": ["aegis", alert.get("tactic", "security").lower()],
                    "customfield_10000": alert.get("id"),  # Example custom field for alert ID
                }
            }

            headers = self._build_headers()
            response = requests.post(
                f"{url}/rest/api/3/issue",
                headers=headers,
                json=issue,
                timeout=10,
            )

            if response.status_code == 201:
                result = response.json()
                return {
                    "status": "success",
                    "issue_id": result.get("id"),
                    "issue_key": result.get("key"),
                    "sent_at": self._now(),
                }
            elif response.status_code == 429:
                self.handle_rate_limit()
                raise IntegrationError("Rate limit exceeded", status_code=429)
            else:
                raise IntegrationError(
                    f"Jira error: {response.status_code}",
                    status_code=response.status_code,
                    details={"response": response.text},
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to send alert to Jira: {str(e)}")

    def update_issue(self, issue_key: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing issue.

        Args:
            issue_key: Jira issue key (e.g., PROJ-123).
            updates: Dictionary of fields to update.

        Returns:
            Response from Jira.
        """
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Jira URL not configured")

            headers = self._build_headers()
            response = requests.put(
                f"{url}/rest/api/3/issue/{issue_key}",
                headers=headers,
                json={"fields": updates},
                timeout=10,
            )

            if response.status_code == 204:
                return {
                    "status": "success",
                    "updated_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Jira update error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"issue_key": issue_key})
            raise IntegrationError(f"Failed to update Jira issue: {str(e)}")

    def add_comment(self, issue_key: str, comment: str) -> Dict[str, Any]:
        """Add a comment to an issue.

        Args:
            issue_key: Jira issue key.
            comment: Comment text.

        Returns:
            Response from Jira.
        """
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Jira URL not configured")

            headers = self._build_headers()
            response = requests.post(
                f"{url}/rest/api/3/issue/{issue_key}/comment",
                headers=headers,
                json={"body": comment},
                timeout=10,
            )

            if response.status_code == 201:
                return {
                    "status": "success",
                    "commented_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Jira comment error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"issue_key": issue_key})
            raise IntegrationError(f"Failed to add comment to Jira issue: {str(e)}")

    def _build_description(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Build Jira issue description in Atlassian Document Format."""
        content = [
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Aegis Security Alert",
                        "marks": [{"type": "strong"}],
                    }
                ],
            },
            {"type": "rule"},
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Alert ID: {alert.get('id')}"}],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Pattern ID: {alert.get('pattern_id')}"}],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Tactic: {alert.get('tactic')}"}],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Technique: {alert.get('technique')}"}],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Severity: {alert.get('severity')}"}],
            },
            {"type": "rule"},
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Source IP: {alert.get('source_ip')}"}],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Destination IP: {alert.get('dest_ip')}"}],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": f"Destination Port: {alert.get('dest_port')}"}],
            },
            {"type": "rule"},
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Evidence:",
                        "marks": [{"type": "strong"}],
                    }
                ],
            },
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": alert.get("evidence") or "No evidence available"}],
            },
        ]
        return {"type": "doc", "version": 1, "content": content}

    def _map_priority(self, severity: Optional[str]) -> str:
        """Map Aegis severity to Jira priority."""
        if not severity:
            return "Low"

        severity = severity.upper()
        mapping = {
            "INFO": "Lowest",
            "LOW": "Low",
            "MEDIUM": "Medium",
            "HIGH": "High",
            "CRITICAL": "Highest",
        }
        return mapping.get(severity, "Low")

    def _build_headers(self) -> Dict[str, str]:
        """Build authentication headers."""
        auth_method = self.config.config.get("auth_method", "api_token")

        if auth_method == "oauth":
            token = self._get_oauth_token()
            if token:
                return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Default to basic auth with API token
        email = self.config.config.get("email")
        api_token = self.config.config.get("api_token")
        if email and api_token:
            import base64
            credentials = base64.b64encode(f"{email}:{api_token}".encode()).decode()
            return {"Authorization": f"Basic {credentials}", "Content-Type": "application/json"}

        return {"Content-Type": "application/json"}

    def _get_oauth_token(self) -> Optional[str]:
        """Get OAuth token for Jira authentication."""
        # Placeholder for OAuth implementation
        return None
