"""Elastic Security (Elasticsearch) integration adapter.

Supports:
- Elasticsearch API for alert and incident indexing
- API key or basic authentication
- Custom index patterns
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class ElasticAdapter(BaseAdapter):
    """Adapter for Elastic Security integration."""

    @property
    def integration_type(self) -> str:
        return "siem"

    def connect(self) -> bool:
        """Establish connection to Elasticsearch."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Elasticsearch URL not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to Elasticsearch."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to Elasticsearch."""
        try:
            url = self.config.config.get("url")
            if not url:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            headers = self._build_headers()
            response = requests.get(f"{url}/", headers=headers, timeout=10)

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
        """Send alert to Elasticsearch."""
        try:
            url = self.config.config.get("url")
            index = self.config.config.get("alert_index", "aegis-alerts")

            if not url:
                raise IntegrationError("Elasticsearch URL not configured")

            headers = self._build_headers()
            doc = {
                "@timestamp": alert.get("timestamp") or alert.get("created_at"),
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
            }

            response = requests.post(
                f"{url}/{index}/_doc",
                headers=headers,
                json=doc,
                timeout=10,
            )

            if response.status_code in (200, 201):
                return {
                    "status": "success",
                    "elasticsearch_id": response.json().get("_id"),
                    "sent_at": self._now(),
                }
            elif response.status_code == 429:
                self.handle_rate_limit()
                raise IntegrationError("Rate limit exceeded", status_code=429)
            else:
                raise IntegrationError(
                    f"Elasticsearch error: {response.status_code}",
                    status_code=response.status_code,
                    details={"response": response.text},
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to send alert to Elasticsearch: {str(e)}")

    def send_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Send incident to Elasticsearch."""
        try:
            url = self.config.config.get("url")
            index = self.config.config.get("incident_index", "aegis-incidents")

            if not url:
                raise IntegrationError("Elasticsearch URL not configured")

            headers = self._build_headers()
            doc = {
                "@timestamp": incident.get("created_at") or incident.get("first_seen"),
                "incident_id": incident.get("id"),
                "title": incident.get("title") or incident.get("narrative"),
                "severity": incident.get("severity"),
                "status": incident.get("status"),
                "source_ips": incident.get("source_ips", []),
                "analyst_assist": incident.get("analyst_assist", {}),
                "loop": incident.get("loop", {}),
                "evidence_count": len(incident.get("alerts", [])),
            }

            response = requests.post(
                f"{url}/{index}/_doc",
                headers=headers,
                json=doc,
                timeout=10,
            )

            if response.status_code in (200, 201):
                return {
                    "status": "success",
                    "elasticsearch_id": response.json().get("_id"),
                    "sent_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Elasticsearch error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"incident_id": incident.get("id")})
            raise IntegrationError(f"Failed to send incident to Elasticsearch: {str(e)}")

    def search(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute a search query in Elasticsearch.

        Args:
            query: Elasticsearch query DSL.

        Returns:
            List of search results.
        """
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Elasticsearch URL not configured")

            headers = self._build_headers()
            response = requests.post(
                f"{url}/_search",
                headers=headers,
                json=query,
                timeout=10,
            )

            if response.status_code == 200:
                hits = response.json().get("hits", {}).get("hits", [])
                return [hit.get("_source") for hit in hits]
            else:
                raise IntegrationError(
                    f"Elasticsearch search error: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"query": query})
            raise IntegrationError(f"Failed to execute Elasticsearch search: {str(e)}")

    def _build_headers(self) -> Dict[str, str]:
        """Build authentication headers."""
        auth_method = self.config.config.get("auth_method", "basic")

        if auth_method == "api_key":
            api_key = self.config.config.get("api_key")
            if api_key:
                return {"Authorization": f"ApiKey {api_key}", "Content-Type": "application/json"}

        # Default to basic auth
        username = self.config.config.get("username")
        password = self.config.config.get("password")
        if username and password:
            import base64
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            return {"Authorization": f"Basic {credentials}", "Content-Type": "application/json"}

        return {"Content-Type": "application/json"}
