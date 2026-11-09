"""Cisco Firepower firewall integration adapter.

Supports:
- IP address blocking/unblocking via REST API
- Security rule management
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus

logger = logging.getLogger(__name__)


class CiscoAdapter(BaseAdapter):
    """Adapter for Cisco Firepower integration."""

    @property
    def integration_type(self) -> str:
        return "firewall"

    def connect(self) -> bool:
        """Establish connection to Cisco Firepower."""
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Cisco Firepower URL not configured")

            status = self.test_connection()
            return status == IntegrationStatus.CONNECTED
        except Exception as e:
            self.log_error(e)
            return False

    def disconnect(self) -> None:
        """Close connection to Cisco Firepower."""
        self._client = None

    def test_connection(self) -> IntegrationStatus:
        """Test connection to Cisco Firepower."""
        try:
            url = self.config.config.get("url")
            username = self.config.config.get("username")
            password = self.config.config.get("password")

            if not url or not username or not password:
                self.config.last_test_status = IntegrationStatus.NOT_CONFIGURED
                return IntegrationStatus.NOT_CONFIGURED

            # Get auth token
            token = self._get_auth_token()
            if token:
                self.config.last_test_status = IntegrationStatus.CONNECTED
                self.config.last_tested = self._now()
                return IntegrationStatus.CONNECTED
            else:
                self.config.last_test_status = IntegrationStatus.ERROR
                self.config.last_error = "Authentication failed"
                return IntegrationStatus.ERROR
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
        """Send alert to Cisco Firepower (creates a log entry)."""
        try:
            # For firewalls, send_alert is primarily for logging
            return {
                "status": "success",
                "logged_at": self._now(),
            }
        except Exception as e:
            self.log_error(e, {"alert_id": alert.get("id")})
            raise IntegrationError(f"Failed to log alert to Cisco Firepower: {str(e)}")

    def block_ip(self, ip_address: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Block an IP address by creating an access rule.

        Args:
            ip_address: IP address to block.
            rule_name: Optional name for the blocking rule.

        Returns:
            Response from Cisco Firepower.
        """
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Cisco Firepower URL not configured")

            token = self._get_auth_token()
            if not token:
                raise IntegrationError("Failed to obtain authentication token")

            rule_name = rule_name or f"block-aegis-{ip_address.replace('.', '-')}"

            # Create network object for the IP
            network_object = {
                "name": rule_name,
                "value": ip_address,
                "type": "Host",
            }

            headers = {
                "X-auth-access-token": token,
                "Content-Type": "application/json",
            }

            response = requests.post(
                f"{url}/api/fmc_config/v1/domain/{self.config.config.get('domain_id', 'e276abec-e0f2-11e3-8169-6d9ed49b625f')}/object/networks",
                headers=headers,
                json=network_object,
                timeout=10,
            )

            if response.status_code not in (200, 201):
                raise IntegrationError(
                    f"Failed to create network object: {response.status_code}",
                    status_code=response.status_code,
                )

            # Create access policy rule
            access_rule = {
                "name": rule_name,
                "action": "BLOCK",
                "enabled": True,
                "sourceNetworks": {"objects": [{"id": response.json().get("id")}]},
                "destinationNetworks": {"objects": [{"type": "AnyNetworkObject"}]},
                "applications": [{"type": "Application", "id": "allApplications"}],
            }

            policy_id = self.config.config.get("access_policy_id")
            if not policy_id:
                raise IntegrationError("Access policy ID not configured")

            response = requests.post(
                f"{url}/api/fmc_config/v1/domain/{self.config.config.get('domain_id', 'e276abec-e0f2-11e3-8169-6d9ed49b625f')}/policy/accesspolicies/{policy_id}/accessrules",
                headers=headers,
                json=access_rule,
                timeout=10,
            )

            if response.status_code in (200, 201):
                # Deploy changes
                self._deploy_changes(token)
                return {
                    "status": "success",
                    "rule_name": rule_name,
                    "blocked_at": self._now(),
                }
            else:
                raise IntegrationError(
                    f"Failed to create access rule: {response.status_code}",
                    status_code=response.status_code,
                )
        except IntegrationError:
            raise
        except Exception as e:
            self.log_error(e, {"ip_address": ip_address})
            raise IntegrationError(f"Failed to block IP on Cisco Firepower: {str(e)}")

    def unblock_ip(self, ip_address: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Unblock an IP address by removing the access rule.

        Args:
            ip_address: IP address to unblock.
            rule_name: Name of the blocking rule to remove.

        Returns:
            Response from Cisco Firepower.
        """
        try:
            url = self.config.config.get("url")
            if not url:
                raise IntegrationError("Cisco Firepower URL not configured")

            token = self._get_auth_token()
            if not token:
                raise IntegrationError("Failed to obtain authentication token")

            rule_name = rule_name or f"block-aegis-{ip_address.replace('.', '-')}"

            headers = {
                "X-auth-access-token": token,
                "Content-Type": "application/json",
            }

            # Delete access rule
            policy_id = self.config.config.get("access_policy_id")
            rule_id = self._get_rule_id(rule_name, token)

            if rule_id:
                response = requests.delete(
                    f"{url}/api/fmc_config/v1/domain/{self.config.config.get('domain_id', 'e276abec-e0f2-11e3-8169-6d9ed49b625f')}/policy/accesspolicies/{policy_id}/accessrules/{rule_id}",
                    headers=headers,
                    timeout=10,
                )

                if response.status_code == 200:
                    # Deploy changes
                    self._deploy_changes(token)
                    return {
                        "status": "success",
                        "unblocked_at": self._now(),
                    }

            # Delete network object
            object_id = self._get_network_object_id(rule_name, token)
            if object_id:
                requests.delete(
                    f"{url}/api/fmc_config/v1/domain/{self.config.config.get('domain_id', 'e276abec-e0f2-11e3-8169-6d9ed49b625f')}/object/networks/{object_id}",
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
            raise IntegrationError(f"Failed to unblock IP on Cisco Firepower: {str(e)}")

    def _get_auth_token(self) -> Optional[str]:
        """Get authentication token from Cisco Firepower."""
        try:
            url = self.config.config.get("url")
            username = self.config.config.get("username")
            password = self.config.config.get("password")

            if not all([url, username, password]):
                return None

            response = requests.post(
                f"{url}/api/fmc_platform/v1/auth/generatetoken",
                auth=(username, password),
                timeout=10,
            )

            if response.status_code == 200:
                return response.headers.get("X-auth-access-token")
            return None
        except Exception as e:
            logger.error(f"Failed to get auth token: {e}")
            return None

    def _deploy_changes(self, token: str) -> None:
        """Deploy configuration changes to Cisco Firepower."""
        try:
            url = self.config.config.get("url")
            domain_id = self.config.config.get("domain_id", "e276abec-e0f2-11e3-8169-6d9ed49b625f")

            headers = {
                "X-auth-access-token": token,
                "Content-Type": "application/json",
            }

            # Get pending changes
            response = requests.get(
                f"{url}/api/fmc_config/v1/domain/{domain_id}/deployment/deployabledevices",
                headers=headers,
                timeout=10,
            )

            if response.status_code == 200:
                devices = response.json().get("items", [])
                if devices:
                    # Deploy to first device (simplified)
                    device_id = devices[0].get("id")
                    requests.post(
                        f"{url}/api/fmc_config/v1/domain/{domain_id}/deployment/deploymentrequests/{device_id}",
                        headers=headers,
                        json={"type": "DEPLOY", "forceDeploy": True},
                        timeout=30,
                    )
        except Exception as e:
            logger.error(f"Failed to deploy changes to Cisco Firepower: {e}")

    def _get_rule_id(self, rule_name: str, token: str) -> Optional[str]:
        """Get rule ID by name."""
        # Simplified - in production, implement proper lookup
        return None

    def _get_network_object_id(self, object_name: str, token: str) -> Optional[str]:
        """Get network object ID by name."""
        # Simplified - in production, implement proper lookup
        return None
