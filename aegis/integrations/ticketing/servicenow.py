"""ServiceNow integration adapter.

Supports:
- Incident creation via REST API
- Incident updates
- OAuth2 and basic authentication
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class ServiceNowAdapter(BaseAdapter):
    """Adapter for ServiceNow integration."""

    @property
    def integration_type(self) -> str:
        return "ticketing"

    def connect(self) -> bool:
        """Establish connection to ServiceNow."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("ServiceNow URL not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to ServiceNow."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to ServiceNow."""
        try:
            url = self.config.config.get("url")
            if not url:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            headers = self._build_headers()
            response = requests.get(f"{url}/api/now/table/incident", headers=headers, timeout=10)

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
        """Send alert to ServiceNow as an incident."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("ServiceNow URL not configured")

            # Format alert as ServiceNow incident
            incident = {
                "short_description": f"Aegis Alert: {alert.get('title')}",
                "description": self._build_description(alert),
                "urgency": self._map_urgency(alert.get("severity")),
                "impact": self._map_impact(alert.get("severity")),
                "priority": self._map_priority(alert.get("severity")),
                "category": "Security",
                "subcategory": "Intrusion Detection",
                "assignment_group": self.config.config.get("assignment_group"),
                "correlation_id": alert.get("id"),
                "u_aegis_alert_id": alert.get("id"),
                "u_aegis_pattern_id": alert.get("pattern_id"),
                "u_source_ip": alert.get("source_ip"),
                "u_dest_ip": alert.get("dest_ip"),
            }

            headers = self._build_headers()
            response = requests.post(
                f"{url}/api/now/table/incident",
                headers=headers,
                json=incident,
                timeout=10,
            )

            if response.status_code == 201:
                result = response.json().get("result", {})
                return {
                    "status": "success",
                    "incident_id": result.get("sys_id"),
                    "incident_number": result.get("number"),
                    "sent_at": self._now(),
                }
            elif response.status_code == 429:
                self.handle_rate_limit()
                raise IntegrationError("Rate limit exceeded", status_code=429)
            else:
                raise IntegrationError(
                    f"ServiceNow error: {response.status_code}",
                    status_code=response.status_code,
                    details={"response": response.text},
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to send alert to ServiceNow: {str(e)}")

    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing incident.

        Args:
            incident_id: ServiceNow incident sys_id.
            updates: Dictionary of fields to update.

        Returns:
            Response from ServiceNow.
        """
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("ServiceNow URL not configured")

            headers = self._build_headers()
            response = requests.patch(
                f"{url}/api/now/table/incident/{incident_id}",
                headers=headers,
                json=updates,
                timeout=10,
            )

            if response.status_code == 200:
                return {
                    "status": "success",
                    "updated_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"ServiceNow update error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"incident_id": incident_id})
            raise IntegrationError(f"Failed to update ServiceNow incident: {str(e)}")

    def _build_description(self, alert: Dict[str, Any]) -> str:
        """Build incident description from alert data."""
        lines = [
            f"Aegis Security Alert",
            f"",
            f"Alert ID: {alert.get('id')}",
            f"Pattern ID: {alert.get('pattern_id')}",
            f"Tactic: {alert.get('tactic')}",
            f"Technique: {alert.get('technique')}",
            f"Severity: {alert.get('severity')}",
            f"",
            f"Source IP: {alert.get('source_ip')}",
            f"Destination IP: {alert.get('dest_ip')}",
            f"Destination Port: {alert.get('dest_port')}",
            f"",
            f"Evidence:",
            f"{alert.get('evidence') or 'No evidence available'}",
        ]
        return "\n".join(lines)

    def _map_urgency(self, severity: Optional[str]) -> str:
        """Map Aegis severity to ServiceNow urgency."""
        if not severity:
            return "3"

        severity = severity.upper()
        mapping = {
            "INFO": "3",
            "LOW": "3",
            "MEDIUM": "2",
            "HIGH": "1",
            "CRITICAL": "1",
        }
        return mapping.get(severity, "3")

    def _map_impact(self, severity: Optional[str]) -> str:
        """Map Aegis severity to ServiceNow impact."""
        if not severity:
            return "3"

        severity = severity.upper()
        mapping = {
            "INFO": "3",
            "LOW": "3",
            "MEDIUM": "2",
            "HIGH": "2",
            "CRITICAL": "1",
        }
        return mapping.get(severity, "3")

    def _map_priority(self, severity: Optional[str]) -> str:
        """Map Aegis severity to ServiceNow priority."""
        if not severity:
            return "5"

        severity = severity.upper()
        mapping = {
            "INFO": "5",
            "LOW": "4",
            "MEDIUM": "3",
            "HIGH": "2",
            "CRITICAL": "1",
        }
        return mapping.get(severity, "5")

    def _build_headers(self) -> Dict[str, str]:
        """Build authentication headers."""
        auth_method = self.config.config.get("auth_method", "basic")

        if auth_method == "oauth2":
            token = self._get_oauth_token()
            if token:
                return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Default to basic auth
        username = self.config.config.get("username")
        password = self.config.config.get("password")
        if username and password:
            import base64
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            return {"Authorization": f"Basic {credentials}", "Content-Type": "application/json"}

        return {"Content-Type": "application/json"}

    def _get_oauth_token(self) -> Optional[str]:
        """Get OAuth2 token for ServiceNow authentication."""
        client_id = self.config.config.get("client_id")
        client_secret = self.config.config.get("client_secret")
        url = self.config.config.get("url")

        if not all([client_id, client_secret, url]):
            return None

        try:
            token_url = f"{url}/oauth_token.do"
            data = {
                "grant_type": "password",
                "client_id": client_id,
                "client_secret": client_secret,
                "username": self.config.config.get("username"),
                "password": self.config.config.get("password"),
            }

            response = requests.post(token_url, data=data, timeout=10)
            if response.status_code == 200:
                return response.json().get("access_token")
            return None
        except Exception as e:
            logger.error(f"Failed to get OAuth2 token: {e}")
            return None
