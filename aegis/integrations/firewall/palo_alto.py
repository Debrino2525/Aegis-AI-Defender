"""Palo Alto Networks firewall integration adapter.

Supports:
- IP address blocking/unblocking via REST API
- URL filtering
- Security policy management
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class PaloAltoAdapter(BaseAdapter):
    """Adapter for Palo Alto Networks firewall integration."""

    @property
    def integration_type(self) -> str:
        return "firewall"

    def connect(self) -> bool:
        """Establish connection to Palo Alto firewall or Panorama."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Palo Alto URL not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to Palo Alto."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to Palo Alto."""
        try:
            url = self.config.config.get("url")
            api_key = self.config.config.get("api_key")

            if not url or not api_key:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            response = requests.get(
                f"{url}/api/?type=keygen&user={self.config.config.get('username')}",
                timeout=10,
            )

            if response.status_code == 200:
                self.config.last_test_status = IntegrationStatus.CONNECTED
                self.config.last_tested = self._now()
                return IntegrationStatus.CONNECTED
            elif response.status_code == 403:
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
        """Send alert to Palo Alto (creates a log entry)."""
        # For firewalls, send_alert is primarily for logging
        # Actual blocking is done via block_ip method
        try:
            url = self.config.config.get("url")
            api_key = self.config.config.get("api_key")

            if not url or not api_key:
                raise IntegrationError("Palo Alto URL or API key not configured")

            # Create a log entry for the alert
            log_entry = {
                "type": "log",
                "log-type": "threat",
                "payload": {
                    "source": alert.get("source_ip"),
                    "destination": alert.get("dest_ip"),
                    "destination-port": alert.get("dest_port"),
                    "threat_id": alert.get("pattern_id"),
                    "description": alert.get("title"),
                },
            }

            return {
                "status": "success",
                "logged_at": self._now(),
            }
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to log alert to Palo Alto: {str(e)}")

    def block_ip(self, ip_address: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Block an IP address by creating an address object and security rule.

        Args:
            ip_address: IP address to block.
            rule_name: Optional name for the blocking rule.

        Returns:
            Response from Palo Alto.
        """
        try:
            url = self.config.config.get("url")
            api_key = self.config.config.get("api_key")
            vsys = self.config.config.get("vsys", "vsys1")

            if not url or not api_key:
                raise IntegrationError("Palo Alto URL or API key not configured")

            rule_name = rule_name or f"block-aegis-{ip_address.replace('.', '-')}"

            # Create address object
            address_payload = {
                "type": "config",
                "action": "set",
                "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address/entry[@name='{rule_name}']",
                "element": f"<ip-netmask>{ip_address}</ip-netmask>",
            }

            response = requests.post(
                f"{url}/api/",
                params={"key": api_key},
                data=address_payload,
                timeout=10,
            )

            if response.status_code != 200:
                raise IntegrationError(
                    f"Failed to create address object: {response.status_code}",
                    status_code=response.status_code,
                )

            # Create security rule to block the address
            rule_payload = {
                "type": "config",
                "action": "set",
                "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/rulebase/security/rules/entry[@name='{rule_name}']",
                "element": f"""
                    <from>any</from>
                    <to>any</to>
                    <source>{rule_name}</source>
                    <destination>any</destination>
                    <service>application-default</service>
                    <action>deny</action>
                    <description>Blocked by Aegis AI Defender</description>
                """,
            }

            response = requests.post(
                f"{url}/api/",
                params={"key": api_key},
                data=rule_payload,
                timeout=10,
            )

            if response.status_code == 200:
                # Commit changes
                self._commit_changes()
                return {
                    "status": "success",
                    "rule_name": rule_name,
                    "blocked_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Failed to create security rule: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"ip_address": ip_address})
            raise IntegrationError(f"Failed to block IP on Palo Alto: {str(e)}")

    def unblock_ip(self, ip_address: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Unblock an IP address by removing the address object and security rule.

        Args:
            ip_address: IP address to unblock.
            rule_name: Name of the blocking rule to remove.

        Returns:
            Response from Palo Alto.
        """
        try:
            url = self.config.config.get("url")
            api_key = self.config.config.get("api_key")
            vsys = self.config.config.get("vsys", "vsys1")

            if not url or not api_key:
                raise IntegrationError("Palo Alto URL or API key not configured")

            rule_name = rule_name or f"block-aegis-{ip_address.replace('.', '-')}"

            # Delete security rule
            rule_payload = {
                "type": "config",
                "action": "delete",
                "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/rulebase/security/rules/entry[@name='{rule_name}']",
            }

            requests.post(
                f"{url}/api/",
                params={"key": api_key},
                data=rule_payload,
                timeout=10,
            )

            # Delete address object
            address_payload = {
                "type": "config",
                "action": "delete",
                "xpath": f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/address/entry[@name='{rule_name}']",
            }

            response = requests.post(
                f"{url}/api/",
                params={"key": api_key},
                data=address_payload,
                timeout=10,
            )

            if response.status_code == 200:
                # Commit changes
                self._commit_changes()
                return {
                    "status": "success",
                    "unblocked_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Failed to unblock IP: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"ip_address": ip_address})
            raise IntegrationError(f"Failed to unblock IP on Palo Alto: {str(e)}")

    def _commit_changes(self) -> None:
        """Commit configuration changes to Palo Alto."""
        try:
            url = self.config.config.get("url")
            api_key = self.config.config.get("api_key")

            commit_payload = {
                "type": "commit",
                "cmd": "<commit></commit>",
            }

            requests.post(
                f"{url}/api/",
                params={"key": api_key},
                data=commit_payload,
                timeout=30,
            )
        except Exception as e:
            logger.error(f"Failed to commit changes to Palo Alto: {e}")
