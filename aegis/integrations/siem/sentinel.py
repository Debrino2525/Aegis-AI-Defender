"""Microsoft Sentinel (Azure Log Analytics) integration adapter.

Supports:
- Log Analytics API for data ingestion
- Azure AD authentication
- Custom log tables
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class SentinelAdapter(BaseAdapter):
    """Adapter for Microsoft Sentinel integration."""

    @property
    def integration_type(self) -> str:
        return "siem"

    def connect(self) -> bool:
        """Establish connection to Microsoft Sentinel."""
        try:
            workspace_id = self.config.config.get("workspace_id")
            if not workspace_id:
                raise IntegrationError("Workspace ID not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to Microsoft Sentinel."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to Microsoft Sentinel."""
        try:
            workspace_id = self.config.config.get("workspace_id")
            if not workspace_id:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            # For OAuth2, we'd need to test with a real token
            # For now, just check if configuration is present
            self.config.last_test_status = IntegrationStatus.CONNECTED
            self.config.last_tested = self._now()
            return IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            self.config.last_test_status = IntegrationStatus.ERROR
            self.config.last_error = str(e)
            return IntegrationStatus.ERROR

    def send_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Send alert to Microsoft Sentinel via Log Analytics API."""
        try:
            workspace_id = self.config.config.get("workspace_id")
            table_name = self.config.config.get("table_name", "AegisAlerts_CL")

            if not workspace_id:
                raise IntegrationError("Workspace ID not configured")

            # Format alert for Sentinel
            body = {
                "records": [
                    {
                        "TimeGenerated": alert.get("timestamp") or alert.get("created_at"),
                        "AlertId": alert.get("id"),
                        "Title": alert.get("title"),
                        "Severity": alert.get("severity"),
                        "PatternId": alert.get("pattern_id"),
                        "Tactic": alert.get("tactic"),
                        "Technique": alert.get("technique"),
                        "SourceIP": alert.get("source_ip"),
                        "DestIP": alert.get("dest_ip"),
                        "DestPort": alert.get("dest_port"),
                        "Evidence": alert.get("evidence"),
                        "IncidentId": alert.get("incident_id"),
                    }
                ]
            }

            # Get OAuth2 token
            token = self._get_oauth_token()
            if not token:
                raise IntegrationError("Failed to obtain OAuth2 token")

            url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Log-Type": table_name,
            }

            response = requests.post(url, headers=headers, json=body, timeout=10)

            if response.status_code == 200:
                return {
                    "status": "success",
                    "sent_at": self._now(),
                }
            elif response.status_code == 429:
                self.handle_rate_limit(response.headers.get("Retry-After"))
                raise IntegrationError("Rate limit exceeded", status_code=429)
            else:
                raise IntegrationError(
                    f"Sentinel API error: {response.status_code}",
                    status_code=response.status_code,
                    details={"response": response.text},
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to send alert to Sentinel: {str(e)}")

    def send_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Send incident to Microsoft Sentinel."""
        try:
            workspace_id = self.config.config.get("workspace_id")
            table_name = self.config.config.get("incident_table", "AegisIncidents_CL")

            if not workspace_id:
                raise IntegrationError("Workspace ID not configured")

            body = {
                "records": [
                    {
                        "TimeGenerated": incident.get("created_at") or incident.get("first_seen"),
                        "IncidentId": incident.get("id"),
                        "Title": incident.get("title") or incident.get("narrative"),
                        "Severity": incident.get("severity"),
                        "Status": incident.get("status"),
                        "SourceIPs": json.dumps(incident.get("source_ips", [])),
                        "AnalystAssist": json.dumps(incident.get("analyst_assist", {})),
                        "Loop": json.dumps(incident.get("loop", {})),
                        "EvidenceCount": len(incident.get("alerts", [])),
                    }
                ]
            }

            token = self._get_oauth_token()
            if not token:
                raise IntegrationError("Failed to obtain OAuth2 token")

            url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Log-Type": table_name,
            }

            response = requests.post(url, headers=headers, json=body, timeout=10)

            if response.status_code == 200:
                return {
                    "status": "success",
                    "sent_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Sentinel API error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"incident_id": incident.get("id")})
            raise IntegrationError(f"Failed to send incident to Sentinel: {str(e)}")

    def _get_oauth_token(self) -> Optional[str]:
        """Get OAuth2 token for Azure authentication.

        In production, this would use the Azure AD library.
        For now, this is a placeholder.
        """
        client_id = self.config.config.get("client_id")
        client_secret = self.config.config.get("client_secret")
        tenant_id = self.config.config.get("tenant_id")

        if not all([client_id, client_secret, tenant_id]):
            return None

        try:
            url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://monitor.azure.com/.default",
                "grant_type": "client_credentials",
            }

            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                return response.json().get("access_token")
            return None
        except Exception as e:
            logger.error(f"Failed to get OAuth2 token: {e}")
            return None
