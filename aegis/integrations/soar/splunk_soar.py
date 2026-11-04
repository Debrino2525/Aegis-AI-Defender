"""Splunk SOAR integration adapter.

Supports:
- Container creation via REST API
- Artifact creation
- Playbook triggering
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class SplunkSoarAdapter(BaseAdapter):
    """Adapter for Splunk SOAR integration."""

    @property
    def integration_type(self) -> str:
        return "soar"

    def connect(self) -> bool:
        """Establish connection to Splunk SOAR."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Splunk SOAR URL not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to Splunk SOAR."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to Splunk SOAR."""
        try:
            url = self.config.config.get("url")
            api_token = self.config.config.get("api_token")

            if not url or not api_token:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            headers = {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            }

            response = requests.get(f"{url}/rest/container", headers=headers, timeout=10)

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
        """Send alert to Splunk SOAR as a container."""
        try:
            url = self.config.config.get("url")
            api_token = self.config.config.get("api_token")

            if not url or not api_token:
                raise IntegrationError("Splunk SOAR URL or API token not configured")

            # Format alert as Splunk SOAR container
            container = {
                "name": f"Aegis Alert: {alert.get('title')}",
                "label": "Aegis Security Alert",
                "description": alert.get("evidence") or alert.get("title"),
                "severity": self._map_severity(alert.get("severity")),
                "artifacts": [
                    {
                        "name": "Alert Details",
                        "type": "aegis_alert",
                        "cef": {
                            "sourceAddress": alert.get("source_ip"),
                            "destinationAddress": alert.get("dest_ip"),
                            "destinationPort": alert.get("dest_port"),
                            "aegisAlertId": alert.get("id"),
                            "aegisPatternId": alert.get("pattern_id"),
                            "aegisTactic": alert.get("tactic"),
                            "aegisTechnique": alert.get("technique"),
                        },
                    }
                ],
            }

            headers = {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            }

            response = requests.post(
                f"{url}/rest/container",
                headers=headers,
                json=container,
                timeout=10,
            )

            if response.status_code in (200, 201):
                return {
                    "status": "success",
                    "container_id": response.json().get("id"),
                    "sent_at": self._now(),
                }
            elif response.status_code == 429:
                self.handle_rate_limit()
                raise IntegrationError("Rate limit exceeded", status_code=429)
            else:
                raise IntegrationError(
                    f"Splunk SOAR error: {response.status_code}",
                    status_code=response.status_code,
                    details={"response": response.text},
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to send alert to Splunk SOAR: {str(e)}")

    def trigger_playbook(self, container_id: str, playbook_id: str) -> Dict[str, Any]:
        """Trigger a playbook on a container.

        Args:
            container_id: Splunk SOAR container ID.
            playbook_id: ID of the playbook to trigger.

        Returns:
            Response from Splunk SOAR.
        """
        try:
            url = self.config.config.get("url")
            api_token = self.config.config.get("api_token")

            if not url or not api_token:
                raise IntegrationError("Splunk SOAR URL or API token not configured")

            headers = {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            }

            body = {
                "playbook_id": playbook_id,
            }

            response = requests.post(
                f"{url}/rest/container/{container_id}/playbook",
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
                    f"Splunk SOAR playbook error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"container_id": container_id, "playbook_id": playbook_id})
            raise IntegrationError(f"Failed to trigger playbook: {str(e)}")

    def _map_severity(self, severity: Optional[str]) -> int:
        """Map Aegis severity to Splunk SOAR severity.

        Splunk SOAR severity: 0=Low, 1=Medium, 2=High, 3=Critical
        """
        if not severity:
            return 0

        severity = severity.upper()
        mapping = {
            "INFO": 0,
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 2,
            "CRITICAL": 3,
        }
        return mapping.get(severity, 0)
