"""Cortex XSOAR integration adapter.

Supports:
- Incident creation via REST API
- Playbook triggering
- API key authentication
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class CortexAdapter(BaseAdapter):
    """Adapter for Cortex XSOAR integration."""

    @property
    def integration_type(self) -> str:
        return "soar"

    def connect(self) -> bool:
        """Establish connection to Cortex XSOAR."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Cortex XSOAR URL not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to Cortex XSOAR."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to Cortex XSOAR."""
        try:
            url = self.config.config.get("url")
            api_key = self.config.config.get("api_key")

            if not url or not api_key:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            headers = {
                "Authorization": api_key,
                "Content-Type": "application/json",
            }

            response = requests.get(f"{url}/incidents", headers=headers, timeout=10)

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
        """Send alert to Cortex XSOAR as an incident."""
        try:
            url = self.config.config.get("url")
            api_key = self.config.config.get("api_key")

            if not url or not api_key:
                raise IntegrationError("Cortex XSOAR URL or API key not configured")

            # Format alert as Cortex incident
            incident = {
                "name": f"Aegis Alert: {alert.get('title')}",
                "type": "Aegis Security Alert",
                "severity": self._map_severity(alert.get("severity")),
                "labels": [
                    "Aegis",
                    alert.get("tactic", "Unknown"),
                    alert.get("pattern_id", ""),
                ],
                "details": json.dumps({
                    "alert_id": alert.get("id"),
                    "pattern_id": alert.get("pattern_id"),
                    "tactic": alert.get("tactic"),
                    "technique": alert.get("technique"),
                    "source_ip": alert.get("source_ip"),
                    "dest_ip": alert.get("dest_ip"),
                    "dest_port": alert.get("dest_port"),
                    "evidence": alert.get("evidence"),
                    "incident_id": alert.get("incident_id"),
                }),
                "customFields": {
                    "aegisalertid": alert.get("id"),
                    "aegispatternid": alert.get("pattern_id"),
                    "aegissourceip": alert.get("source_ip"),
                },
            }

            headers = {
                "Authorization": api_key,
                "Content-Type": "application/json",
            }

            response = requests.post(
                f"{url}/incident",
                headers=headers,
                json=incident,
                timeout=10,
            )

            if response.status_code in (200, 201):
                return {
                    "status": "success",
                    "cortex_incident_id": response.json().get("id"),
                    "sent_at": self._now(),
                }
            elif response.status_code == 429:
                self.handle_rate_limit()
                raise IntegrationError("Rate limit exceeded", status_code=429)
            else:
                raise IntegrationError(
                    f"Cortex XSOAR error: {response.status_code}",
                    status_code=response.status_code,
                    details={"response": response.text},
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to send alert to Cortex XSOAR: {str(e)}")

    def trigger_playbook(self, incident_id: str, playbook_name: str) -> Dict[str, Any]:
        """Trigger a playbook on an incident.

        Args:
            incident_id: Cortex XSOAR incident ID.
            playbook_name: Name of the playbook to trigger.

        Returns:
            Response from Cortex XSOAR.
        """
        try:
            url = self.config.config.get("url")
            api_key = self.config.config.get("api_key")

            if not url or not api_key:
                raise IntegrationError("Cortex XSOAR URL or API key not configured")

            headers = {
                "Authorization": api_key,
                "Content-Type": "application/json",
            }

            body = {
                "playbookId": playbook_name,
            }

            response = requests.post(
                f"{url}/incidents/{incident_id}/playbook/execute",
                headers=headers,
                json=body,
                timeout=10,
            )

            if response.status_code in (200, 201):
                return {
                    "status": "success",
                    "triggered_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Cortex XSOAR playbook error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"incident_id": incident_id, "playbook": playbook_name})
            raise IntegrationError(f"Failed to trigger playbook: {str(e)}")

    def _map_severity(self, severity: Optional[str]) -> int:
        """Map Aegis severity to Cortex XSOAR severity.

        Cortex XSOAR severity: 0=Unknown, 1=Low, 2=Medium, 3=High, 4=Critical
        """
        if not severity:
            return 0

        severity = severity.upper()
        mapping = {
            "INFO": 1,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return mapping.get(severity, 0)
