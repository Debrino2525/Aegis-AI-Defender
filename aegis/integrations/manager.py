"""Integration manager for handling all external system integrations.

Provides centralized management of integration adapters, configuration,
and alert/incident routing to configured systems.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationError, IntegrationStatus
from aegis.integrations.siem import SplunkAdapter, SentinelAdapter, ElasticAdapter
from aegis.integrations.soar import CortexAdapter, SplunkSoarAdapter
from aegis.integrations.ticketing import ServiceNowAdapter, JiraAdapter
from aegis.integrations.firewall import PaloAltoAdapter, CiscoAdapter, FortinetAdapter

logger = logging.getLogger(__name__)

ADAPTER_MAP = {
    "splunk": SplunkAdapter,
    "microsoft_sentinel": SentinelAdapter,
    "elastic_security": ElasticAdapter,
    "cortex_xsoar": CortexAdapter,
    "splunk_soar": SplunkSoarAdapter,
    "servicenow": ServiceNowAdapter,
    "jira": JiraAdapter,
    "palo_alto": PaloAltoAdapter,
    "cisco_firepower": CiscoAdapter,
    "fortinet": FortinetAdapter,
}


class IntegrationManager:
    """Central manager for all integrations."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path.home() / ".aegis" / "integrations.json"
        self.adapters: Dict[str, BaseAdapter] = {}
        self.configs: Dict[str, IntegrationConfig] = {}
        self._load_configs()

    def _load_configs(self) -> None:
        """Load integration configurations from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                    for integration_id, config_data in data.items():
                        self.configs[integration_id] = IntegrationConfig(
                            integration_id=integration_id,
                            name=config_data.get("name", integration_id),
                            type=config_data.get("type", "unknown"),
                            enabled=config_data.get("enabled", False),
                            config=config_data.get("config", {}),
                            capabilities=config_data.get("capabilities", []),
                            last_tested=config_data.get("last_tested"),
                            last_test_status=IntegrationStatus(config_data.get("last_test_status")) if config_data.get("last_test_status") else None,
                            last_error=config_data.get("last_error"),
                            rate_limit_reset=config_data.get("rate_limit_reset"),
                        )
            except Exception as e:
                logger.error(f"Failed to load integration configs: {e}")

    def _save_configs(self) -> None:
        """Save integration configurations to file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            for integration_id, config in self.configs.items():
                data[integration_id] = {
                    "name": config.name,
                    "type": config.type,
                    "enabled": config.enabled,
                    "config": config.config,
                    "capabilities": config.capabilities,
                    "last_tested": config.last_tested,
                    "last_test_status": config.last_test_status.value if config.last_test_status else None,
                    "last_error": config.last_error,
                    "rate_limit_reset": config.rate_limit_reset,
                }
            with open(self.config_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save integration configs: {e}")

    def list_integrations(self) -> List[Dict[str, Any]]:
        """List all integrations with their status."""
        from aegis.integrations import list_available_integrations

        available = {item["id"]: item for item in list_available_integrations()}
        result = []

        for integration_id, adapter_class in ADAPTER_MAP.items():
            meta = available.get(integration_id, {})
            config = self.configs.get(integration_id)
            adapter = self.adapters.get(integration_id)

            status = {
                "id": integration_id,
                "name": meta.get("name", integration_id),
                "type": meta.get("type", "unknown"),
                "capabilities": meta.get("capabilities", []),
                "enabled": config.enabled if config else False,
                "configured": config is not None,
                "connected": adapter is not None and adapter.is_connected(),
                "last_tested": config.last_tested if config else None,
                "last_test_status": config.last_test_status.value if config and config.last_test_status else None,
                "last_error": config.last_error if config else None,
            }
            result.append(status)

        return result

    def get_integration(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific integration."""
        adapter_class = ADAPTER_MAP.get(integration_id)
        if not adapter_class:
            return None

        config = self.configs.get(integration_id)
        adapter = self.adapters.get(integration_id)

        return {
            "id": integration_id,
            "config": config.get_config() if config else None,
            "connected": adapter.is_connected() if adapter else False,
        }

    def configure_integration(self, integration_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure an integration.

        Args:
            integration_id: ID of the integration to configure.
            config: Configuration parameters.

        Returns:
            Updated configuration.
        """
        adapter_class = ADAPTER_MAP.get(integration_id)
        if not adapter_class:
            raise IntegrationError(f"Unknown integration: {integration_id}")

        # Create or update config
        integration_config = self.configs.get(integration_id)
        if not integration_config:
            from aegis.integrations import list_available_integrations
            available = {item["id"]: item for item in list_available_integrations()}
            meta = available.get(integration_id, {})

            integration_config = IntegrationConfig(
                integration_id=integration_id,
                name=config.get("name", meta.get("name", integration_id)),
                type=meta.get("type", "unknown"),
                enabled=config.get("enabled", False),
                config=config,
                capabilities=meta.get("capabilities", []),
            )
        else:
            integration_config.config.update(config)
            if "enabled" in config:
                integration_config.enabled = config["enabled"]

        self.configs[integration_id] = integration_config
        self._save_configs()

        # Reconnect if enabled
        if integration_config.enabled:
            self.connect_integration(integration_id)

        return integration_config.get_config()

    def connect_integration(self, integration_id: str) -> Dict[str, Any]:
        """Connect to an integration.

        Args:
            integration_id: ID of the integration to connect.

        Returns:
            Connection status.
        """
        adapter_class = ADAPTER_MAP.get(integration_id)
        config = self.configs.get(integration_id)

        if not adapter_class:
            raise IntegrationError(f"Unknown integration: {integration_id}")
        if not config:
            raise IntegrationError(f"Integration not configured: {integration_id}")

        # Create adapter instance
        adapter = adapter_class(config)
        success = adapter.connect()

        if success:
            self.adapters[integration_id] = adapter
            config.last_test_status = IntegrationStatus.CONNECTED
            config.last_tested = adapter._now()
        else:
            config.last_test_status = IntegrationStatus.ERROR
            config.last_error = "Connection failed"

        self._save_configs()
        return {
            "connected": success,
            "status": config.last_test_status.value if config.last_test_status else None,
        }

    def disconnect_integration(self, integration_id: str) -> Dict[str, Any]:
        """Disconnect from an integration.

        Args:
            integration_id: ID of the integration to disconnect.

        Returns:
            Disconnection status.
        """
        adapter = self.adapters.get(integration_id)
        if adapter:
            adapter.disconnect()
            del self.adapters[integration_id]

        config = self.configs.get(integration_id)
        if config:
            config.last_test_status = IntegrationStatus.DISCONNECTED
            self._save_configs()

        return {"disconnected": True}

    def test_integration(self, integration_id: str) -> Dict[str, Any]:
        """Test connection to an integration.

        Args:
            integration_id: ID of the integration to test.

        Returns:
            Test result.
        """
        adapter = self.adapters.get(integration_id)
        if not adapter:
            # Try to connect first
            self.connect_integration(integration_id)
            adapter = self.adapters.get(integration_id)

        if not adapter:
            return {"status": "error", "message": "Adapter not available"}

        status = adapter.test_connection()
        config = self.configs.get(integration_id)
        if config:
            config.last_test_status = status
            config.last_tested = adapter._now()
            self._save_configs()

        return {
            "status": status.value,
            "tested_at": config.last_tested if config else None,
        }

    def send_alert(self, alert: Dict[str, Any], integration_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Send an alert to configured integrations.

        Args:
            alert: Alert data.
            integration_ids: Optional list of integration IDs to send to. If None, sends to all enabled SIEM/SOAR/ticketing integrations.

        Returns:
            Results from each integration.
        """
        if integration_ids is None:
            # Send to all enabled SIEM, SOAR, and ticketing integrations
            integration_ids = [
                iid for iid, config in self.configs.items()
                if config.enabled and config.type in ("siem", "soar", "ticketing")
            ]

        results = {}
        for integration_id in integration_ids:
            adapter = self.adapters.get(integration_id)
            if not adapter or not adapter.is_connected():
                results[integration_id] = {"status": "error", "message": "Not connected"}
                continue

            try:
                result = adapter.send_alert(alert)
                results[integration_id] = result
            except IntegrationError as e:
                results[integration_id] = {"status": "error", "message": str(e)}
                logger.error(f"Failed to send alert to {integration_id}: {e}")

        return results

    def send_incident(self, incident: Dict[str, Any], integration_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Send an incident to configured integrations.

        Args:
            incident: Incident data.
            integration_ids: Optional list of integration IDs to send to.

        Returns:
            Results from each integration.
        """
        if integration_ids is None:
            integration_ids = [
                iid for iid, config in self.configs.items()
                if config.enabled and config.type in ("siem", "soar", "ticketing")
            ]

        results = {}
        for integration_id in integration_ids:
            adapter = self.adapters.get(integration_id)
            if not adapter or not adapter.is_connected():
                results[integration_id] = {"status": "error", "message": "Not connected"}
                continue

            try:
                if hasattr(adapter, "send_incident"):
                    result = adapter.send_incident(incident)
                    results[integration_id] = result
                else:
                    results[integration_id] = {"status": "error", "message": "Method not supported"}
            except IntegrationError as e:
                results[integration_id] = {"status": "error", "message": str(e)}
                logger.error(f"Failed to send incident to {integration_id}: {e}")

        return results

    def block_ip(self, ip_address: str, integration_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Block an IP address on configured firewall integrations.

        Args:
            ip_address: IP address to block.
            integration_ids: Optional list of firewall integration IDs. If None, uses all enabled firewalls.

        Returns:
            Results from each firewall.
        """
        if integration_ids is None:
            integration_ids = [
                iid for iid, config in self.configs.items()
                if config.enabled and config.type == "firewall"
            ]

        results = {}
        for integration_id in integration_ids:
            adapter = self.adapters.get(integration_id)
            if not adapter or not adapter.is_connected():
                results[integration_id] = {"status": "error", "message": "Not connected"}
                continue

            try:
                if hasattr(adapter, "block_ip"):
                    result = adapter.block_ip(ip_address)
                    results[integration_id] = result
                else:
                    results[integration_id] = {"status": "error", "message": "Method not supported"}
            except IntegrationError as e:
                results[integration_id] = {"status": "error", "message": str(e)}
                logger.error(f"Failed to block IP on {integration_id}: {e}")

        return results

    def unblock_ip(self, ip_address: str, integration_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Unblock an IP address on configured firewall integrations.

        Args:
            ip_address: IP address to unblock.
            integration_ids: Optional list of firewall integration IDs.

        Returns:
            Results from each firewall.
        """
        if integration_ids is None:
            integration_ids = [
                iid for iid, config in self.configs.items()
                if config.enabled and config.type == "firewall"
            ]

        results = {}
        for integration_id in integration_ids:
            adapter = self.adapters.get(integration_id)
            if not adapter or not adapter.is_connected():
                results[integration_id] = {"status": "error", "message": "Not connected"}
                continue

            try:
                if hasattr(adapter, "unblock_ip"):
                    result = adapter.unblock_ip(ip_address)
                    results[integration_id] = result
                else:
                    results[integration_id] = {"status": "error", "message": "Method not supported"}
            except IntegrationError as e:
                results[integration_id] = {"status": "error", "message": str(e)}
                logger.error(f"Failed to unblock IP on {integration_id}: {e}")

        return results


# Global instance
_integration_manager: Optional[IntegrationManager] = None


def get_integration_manager() -> IntegrationManager:
    """Get the global integration manager instance."""
    global _integration_manager
    if _integration_manager is None:
        _integration_manager = IntegrationManager()
    return _integration_manager
