"""Tests for integration adapters."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from aegis.integrations.base import BaseAdapter, IntegrationConfig, IntegrationStatus, IntegrationError
from aegis.integrations.manager import IntegrationManager, get_integration_manager
from aegis.integrations.siem import SplunkAdapter, SentinelAdapter, ElasticAdapter
from aegis.integrations.soar import CortexAdapter, SplunkSoarAdapter
from aegis.integrations.ticketing import ServiceNowAdapter, JiraAdapter
from aegis.integrations.firewall import PaloAltoAdapter, CiscoAdapter, FortinetAdapter


@pytest.fixture
def temp_config_path(tmp_path):
    """Temporary config path for testing."""
    return tmp_path / "integrations.json"


@pytest.fixture
def integration_manager(temp_config_path):
    """Integration manager instance with temp config."""
    manager = IntegrationManager(config_path=temp_config_path)
    yield manager
    # Cleanup
    if temp_config_path.exists():
        temp_config_path.unlink()


@pytest.fixture
def sample_config():
    """Sample integration configuration."""
    return IntegrationConfig(
        integration_id="test_integration",
        name="Test Integration",
        type="siem",
        enabled=False,
        config={"url": "https://test.example.com", "api_key": "test-key"},
        capabilities=["alert_output"],
    )


class TestBaseAdapter:
    """Tests for BaseAdapter."""

    def test_adapter_initialization(self, sample_config):
        """Test adapter initialization with config."""
        class TestAdapter(BaseAdapter):
            @property
            def integration_type(self):
                return "test"

            def connect(self):
                return True

            def disconnect(self):
                pass

            def test_connection(self):
                return IntegrationStatus.CONNECTED

            def send_alert(self, alert):
                return {"status": "success"}

        adapter = TestAdapter(sample_config)
        assert adapter.config == sample_config
        assert adapter.integration_type == "test"

    def test_mask_secrets(self, sample_config):
        """Test secret masking in configuration."""
        class TestAdapter(BaseAdapter):
            @property
            def integration_type(self):
                return "test"

            def connect(self):
                return True

            def disconnect(self):
                pass

            def test_connection(self):
                return IntegrationStatus.CONNECTED

            def send_alert(self, alert):
                return {"status": "success"}

        adapter = TestAdapter(sample_config)
        data = {"api_key": "secret123", "password": "pass456", "username": "user"}
        masked = adapter.mask_secrets(data, ["api_key", "password"])
        assert masked["api_key"] == "********"
        assert masked["password"] == "********"
        assert masked["username"] == "user"


class TestIntegrationManager:
    """Tests for IntegrationManager."""

    def test_manager_initialization(self, temp_config_path):
        """Test manager initialization."""
        manager = IntegrationManager(config_path=temp_config_path)
        assert manager.config_path == temp_config_path
        assert manager.adapters == {}
        assert manager.configs == {}

    def test_list_integrations(self, integration_manager):
        """Test listing all integrations."""
        integrations = integration_manager.list_integrations()
        assert len(integrations) > 0
        assert any(i["id"] == "splunk" for i in integrations)
        assert any(i["id"] == "servicenow" for i in integrations)
        assert any(i["id"] == "palo_alto" for i in integrations)

    def test_configure_integration(self, integration_manager):
        """Test configuring an integration."""
        config = {
            "enabled": False,
            "url": "https://splunk.example.com",
            "hec_token": "test-token",
        }
        result = integration_manager.configure_integration("splunk", config)
        assert "splunk" in integration_manager.configs
        assert integration_manager.configs["splunk"].config["url"] == "https://splunk.example.com"

    def test_configure_unknown_integration(self, integration_manager):
        """Test configuring an unknown integration raises error."""
        with pytest.raises(IntegrationError):
            integration_manager.configure_integration("unknown", {})

    def test_get_integration(self, integration_manager):
        """Test getting integration details."""
        integration_manager.configure_integration("splunk", {"enabled": False, "url": "https://test.com"})
        integration = integration_manager.get_integration("splunk")
        assert integration is not None
        assert integration["id"] == "splunk"

    def test_get_unknown_integration(self, integration_manager):
        """Test getting unknown integration returns None."""
        integration = integration_manager.get_integration("unknown")
        assert integration is None


class TestSplunkAdapter:
    """Tests for Splunk adapter."""

    def test_adapter_type(self):
        """Test adapter type is siem."""
        config = IntegrationConfig(
            integration_id="splunk",
            name="Splunk",
            type="siem",
            enabled=False,
            config={},
            capabilities=[],
        )
        adapter = SplunkAdapter(config)
        assert adapter.integration_type == "siem"

    @patch("requests.get")
    def test_test_connection_success(self, mock_get):
        """Test successful connection test."""
        mock_get.return_value.status_code = 200
        config = IntegrationConfig(
            integration_id="splunk",
            name="Splunk",
            type="siem",
            enabled=False,
            config={"hec_url": "https://splunk.example.com", "hec_token": "test"},
            capabilities=[],
        )
        adapter = SplunkAdapter(config)
        status = adapter.test_connection()
        assert status == IntegrationStatus.CONNECTED

    @patch("requests.get")
    def test_test_connection_auth_failure(self, mock_get):
        """Test connection test with auth failure."""
        mock_get.return_value.status_code = 401
        config = IntegrationConfig(
            integration_id="splunk",
            name="Splunk",
            type="siem",
            enabled=False,
            config={"hec_url": "https://splunk.example.com", "hec_token": "test"},
            capabilities=[],
        )
        adapter = SplunkAdapter(config)
        status = adapter.test_connection()
        assert status == IntegrationStatus.ERROR


class TestServiceNowAdapter:
    """Tests for ServiceNow adapter."""

    def test_adapter_type(self):
        """Test adapter type is ticketing."""
        config = IntegrationConfig(
            integration_id="servicenow",
            name="ServiceNow",
            type="ticketing",
            enabled=False,
            config={},
            capabilities=[],
        )
        adapter = ServiceNowAdapter(config)
        assert adapter.integration_type == "ticketing"

    def test_severity_mapping(self):
        """Test severity mapping to ServiceNow urgency."""
        config = IntegrationConfig(
            integration_id="servicenow",
            name="ServiceNow",
            type="ticketing",
            enabled=False,
            config={},
            capabilities=[],
        )
        adapter = ServiceNowAdapter(config)
        assert adapter._map_urgency("CRITICAL") == "1"
        assert adapter._map_urgency("HIGH") == "1"
        assert adapter._map_urgency("MEDIUM") == "2"
        assert adapter._map_urgency("LOW") == "3"
        assert adapter._map_urgency("INFO") == "3"


class TestPaloAltoAdapter:
    """Tests for Palo Alto adapter."""

    def test_adapter_type(self):
        """Test adapter type is firewall."""
        config = IntegrationConfig(
            integration_id="palo_alto",
            name="Palo Alto",
            type="firewall",
            enabled=False,
            config={},
            capabilities=[],
        )
        adapter = PaloAltoAdapter(config)
        assert adapter.integration_type == "firewall"


class TestIntegrationAPI:
    """Tests for integration API endpoints."""

    def test_list_available_integrations(self):
        """Test listing available integrations."""
        from aegis.integrations import list_available_integrations
        integrations = list_available_integrations()
        assert len(integrations) > 0
        assert all("id" in i for i in integrations)
        assert all("type" in i for i in integrations)
        assert all("capabilities" in i for i in integrations)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
