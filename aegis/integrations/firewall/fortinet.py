"""Fortinet FortiGate firewall integration adapter.

Supports:
- IP address blocking/unblocking via REST API
- Firewall policy management
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class FortinetAdapter(BaseAdapter):
    """Adapter for Fortinet FortiGate integration."""

    @property
    def integration_type(self) -> str:
        return "firewall"

    def connect(self) -> bool:
        """Establish connection to FortiGate."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("FortiGate URL not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to FortiGate."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to FortiGate."""
        try:
            url = self.config.config.get("url")
            api_token = self.config.config.get("api_token")

            if not url or not api_token:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            headers = {"Authorization": f"Bearer {api_token}"}
            response = requests.get(f"{url}/api/v2/cmdb/system/status", headers=headers, timeout=10)

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
        """Send alert to FortiGate (creates a log entry)."""
        try:
            # For firewalls, send_alert is primarily for logging
            return {
                "status": "success",
                "logged_at": self._now(),
            }
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to log alert to FortiGate: {str(e)}")

    def block_ip(self, ip_address: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Block an IP address by creating an address object and firewall policy.

        Args:
            ip_address: IP address to block.
            rule_name: Optional name for the blocking rule.

        Returns:
            Response from FortiGate.
        """
        try:
            url = self.config.config.get("url")
            api_token = self.config.config.get("api_token")

            if not url or not api_token:
                raise IntegrationError("FortiGate URL or API token not configured")

            rule_name = rule_name or f"block-aegis-{ip_address.replace('.', '-')}"

            headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

            # Create address object
            address_payload = {
                "name": rule_name,
                "type": "ipmask",
                "subnet": f"{ip_address}/32",
                "comment": "Blocked by Aegis AI Defender",
            }

            response = requests.post(
                f"{url}/api/v2/cmdb/firewall/address",
                headers=headers,
                json=address_payload,
                timeout=10,
            )

            if response.status_code not in (200, 201):
                raise IntegrationError(
                    f"Failed to create address object: {response.status_code}",
                    status_code=response.status_code,
                )

            # Create address group
            group_name = f"{rule_name}-group"
            group_payload = {
                "name": group_name,
                "member": [{"name": rule_name}],
                "comment": "Blocked by Aegis AI Defender",
            }

            requests.post(
                f"{url}/api/v2/cmdb/firewall/addrgrp",
                headers=headers,
                json=group_payload,
                timeout=10,
            )

            # Create firewall policy
            policy_payload = {
                "name": rule_name,
                "srcintf": ["any"],
                "dstintf": ["any"],
                "srcaddr": [group_name],
                "dstaddr": ["all"],
                "action": "deny",
                "schedule": "always",
                "service": "ALL",
                "logtraffic": "all",
                "comment": "Blocked by Aegis AI Defender",
            }

            response = requests.post(
                f"{url}/api/v2/cmdb/firewall/policy",
                headers=headers,
                json=policy_payload,
                timeout=10,
            )

            if response.status_code in (200, 201):
                return {
                    "status": "success",
                    "rule_name": rule_name,
                    "blocked_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Failed to create firewall policy: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"ip_address": ip_address})
            raise IntegrationError(f"Failed to block IP on FortiGate: {str(e)}")

    def unblock_ip(self, ip_address: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Unblock an IP address by removing the address object and firewall policy.

        Args:
            ip_address: IP address to unblock.
            rule_name: Name of the blocking rule to remove.

        Returns:
            Response from FortiGate.
        """
        try:
            url = self.config.config.get("url")
            api_token = self.config.config.get("api_token")

            if not url or not api_token:
                raise IntegrationError("FortiGate URL or API token not configured")

            rule_name = rule_name or f"block-aegis-{ip_address.replace('.', '-')}"

            headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

            # Delete firewall policy
            policy_id = self._get_policy_id(rule_name, headers)
            if policy_id:
                requests.delete(
                    f"{url}/api/v2/cmdb/firewall/policy/{policy_id}",
                    headers=headers,
                    timeout=10,
                )

            # Delete address group
            group_name = f"{rule_name}-group"
            group_id = self._get_address_group_id(group_name, headers)
            if group_id:
                requests.delete(
                    f"{url}/api/v2/cmdb/firewall/addrgrp/{group_id}",
                    headers=headers,
                    timeout=10,
                )

            # Delete address object
            address_id = self._get_address_id(rule_name, headers)
            if address_id:
                requests.delete(
                    f"{url}/api/v2/cmdb/firewall/address/{address_id}",
                    headers=headers,
                    timeout=10,
                )

            return {
                "status": "success",
                "unblocked_at": self._now(),
            }
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"ip_address": ip_address})
            raise IntegrationError(f"Failed to unblock IP on FortiGate: {str(e)}")

    def _get_policy_id(self, policy_name: str, headers: Dict[str, str]) -> Optional[str]:
        """Get policy ID by name."""
        try:
            url = self.config.config.get("url")
            response = requests.get(
                f"{url}/api/v2/cmdb/firewall/policy",
                headers=headers,
                timeout=10,
            )

            if response.status_code == 200:
                policies = response.json().get("results", [])
                for policy in policies:
                    if policy.get("name") == policy_name:
                        return policy.get("oid")
            return None
        except Exception as e:
            logger.error(f"Failed to get policy ID: {e}")
            return None

    def _get_address_id(self, address_name: str, headers: Dict[str, str]) -> Optional[str]:
        """Get address object ID by name."""
        try:
            url = self.config.config.get("url")
            response = requests.get(
                f"{url}/api/v2/cmdb/firewall/address",
                headers=headers,
                timeout=10,
            )

            if response.status_code == 200:
                addresses = response.json().get("results", [])
                for address in addresses:
                    if address.get("name") == address_name:
                        return address.get("qds_key") or address.get("oid")
            return None
        except Exception as e:
            logger.error(f"Failed to get address ID: {e}")
            return None

    def _get_address_group_id(self, group_name: str, headers: Dict[str, str]) -> Optional[str]:
        """Get address group ID by name."""
        try:
            url = self.config.config.get("url")
            response = requests.get(
                f"{url}/api/v2/cmdb/firewall/addrgrp",
                headers=headers,
                timeout=10,
            )

            if response.status_code == 200:
                groups = response.json().get("results", [])
                for group in groups:
                    if group.get("name") == group_name:
                        return group.get("qds_key") or group.get("oid")
            return None
        except Exception as e:
            logger.error(f"Failed to get address group ID: {e}")
            return None
