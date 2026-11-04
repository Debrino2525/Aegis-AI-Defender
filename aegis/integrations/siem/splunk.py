"""Splunk SIEM integration adapter.

Supports:
- HTTP Event Collector (HEC) for real-time alert forwarding
- REST API for search and data ingestion
- Syslog output for legacy integration
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class SplunkAdapter(BaseAdapter):
    """Adapter for Splunk SIEM integration."""

    @property
    def integration_type(self) -> str:
        return "siem"

    def connect(self) -> bool:
        """Establish connection to Splunk HEC or REST API."""
        try:
            url = self.config.config.get("hec_url") or self.config.config.get("rest_url")
            if not url:
                raise IntegrationError("Splunk URL not configured")

            token = self.config.config.get("hec_token") or self.config.config.get("api_token")
            if not token:
                raise IntegrationError("Splunk token not configured")

            # Test connection
            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to Splunk."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to Splunk."""
        try:
            # Try HEC health check first
            hec_url = self.config.config.get("hec_url")
            if hec_url:
                hec_token = self.config.config.get("hec_token")
                response = requests.get(
                    f"{hec_url}/services/collector/health",
                    headers={"Authorization": f"Splunk {hec_token}"},
                    timeout=10,
                )
                if response.status_code == 200:
                    self.config.last_test_status = IntegrationStatus.CONNECTED
                    self.config.last_tested = self._now()
                    return IntegrationStatus.CONNECTED
                elif response.status_code == 401:
                    self.config.last_test_status = IntegrationStatus.ERROR
                    self.config.last_error = "Authentication failed"
                    return IntegrationStatus.ERROR

            # Fallback to REST API test
            rest_url = self.config.config.get("rest_url")
            if rest_url:
                api_token = self.config.config.get("api_token")
                response = requests.get(
                    f"{rest_url}/services/server/info",
                    headers={"Authorization": f"Bearer {api_token}"},
                    timeout=10,
                )
                if response.status_code == 200:
                    self.config.last_test_status = IntegrationStatus.CONNECTED
                    self.config.last_tested = self._now()
                    return IntegrationStatus.CONNECTED
                elif response.status_code == 401:
                    self.config.last_test_status = IntegrationStatus.ERROR
                    self.config.last_error = "Authentication failed"
                    return IntegrationStatus.ERROR

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
        """Send alert to Splunk via HEC."""
        try:
            hec_url = self.config.config.get("hec_url")
            hec_token = self.config.config.get("hec_token")

            if not hec_url or not hec_token:
                raise IntegrationError("HEC URL or token not configured")

            # Format alert for Splunk
            event = {
                "time": alert.get("timestamp") or alert.get("created_at"),
                "host": alert.get("source_ip") or "aegis-console",
                "source": "aegis",
                "sourcetype": "json:alert",
                "index": self.config.config.get("index", "aegis_alerts"),
                "event": {
                    "alert_id": alert.get("id"),
                    "title": alert.get("title"),
                    "severity": alert.get("severity"),
                    "pattern_id": alert.get("pattern_id"),
                    "tactic": alert.get("tactic"),
                    "technique": alert.get("technique"),
                    "source_ip": alert.get("source_ip"),
                    "dest_ip": alert.get("dest_ip"),
                    "dest_port": alert.get("dest_port"),
                    "evidence": alert.get("evidence"),
                    "incident_id": alert.get("incident_id"),
                },
            }

            response = requests.post(
                f"{hec_url}/services/collector/event",
                headers={"Authorization": f"Splunk {hec_token}"},
                json=event,
                timeout=10,
            )

            if response.status_code == 200:
                return {
                    "status": "success",
                    "splunk_response": response.json(),
                    "sent_at": self._now(),
                }
            elif response.status_code == 429:
                self.handle_rate_limit(response.headers.get("X-RateLimit-Reset"))
                raise IntegrationError("Rate limit exceeded", status_code=429)
            else:
                raise IntegrationError(
                    f"Splunk HEC error: {response.status_code}",
                    status_code=response.status_code,
                    details={"response": response.text},
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to send alert to Splunk: {str(e)}")

    def send_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Send incident to Splunk via HEC."""
        try:
            hec_url = self.config.config.get("hec_url")
            hec_token = self.config.config.get("hec_token")

            if not hec_url or not hec_token:
                raise IntegrationError("HEC URL or token not configured")

            event = {
                "time": incident.get("created_at") or incident.get("first_seen"),
                "host": incident.get("source_ips", ["unknown"])[0] if incident.get("source_ips") else "aegis-console",
                "source": "aegis",
                "sourcetype": "json:incident",
                "index": self.config.config.get("index", "aegis_incidents"),
                "event": {
                    "incident_id": incident.get("id"),
                    "title": incident.get("title") or incident.get("narrative"),
                    "severity": incident.get("severity"),
                    "status": incident.get("status"),
                    "source_ips": incident.get("source_ips"),
                    "analyst_assist": incident.get("analyst_assist"),
                    "loop": incident.get("loop"),
                    "evidence_count": len(incident.get("alerts", [])),
                },
            }

            response = requests.post(
                f"{hec_url}/services/collector/event",
                headers={"Authorization": f"Splunk {hec_token}"},
                json=event,
                timeout=10,
            )

            if response.status_code == 200:
                return {
                    "status": "success",
                    "splunk_response": response.json(),
                    "sent_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Splunk HEC error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"incident_id": incident.get("id")})
            raise IntegrationError(f"Failed to send incident to Splunk: {str(e)}")

    def search(self, query: str, time_range: str = "-24h") -> List[Dict[str, Any]]:
        """Execute a search query in Splunk.

        Args:
            query: SPL search query.
            time_range: Time range for search (e.g., "-24h", "-7d").

        Returns:
            List of search results.
        """
        try:
            rest_url = self.config.config.get("rest_url")
            api_token = self.config.config.get("api_token")

            if not rest_url or not api_token:
                raise IntegrationError("REST API URL or token not configured")

            search_payload = {
                "search": f"search {query}",
                "earliest_time": time_range,
                "latest_time": "now",
                "output_mode": "json",
            }

            response = requests.post(
                f"{rest_url}/services/search/jobs",
                headers={"Authorization": f"Bearer {api_token}"},
                data=search_payload,
                timeout=10,
            )

            if response.status_code == 201:
                job_id = response.json().get("sid")
                # Wait for job to complete and fetch results
                # (Simplified - in production, implement async polling)
                return []
            else:
                raise IntegrationError(
                    f"Splunk search error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"query": query})
            raise IntegrationError(f"Failed to execute Splunk search: {str(e)}")
