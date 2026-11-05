"""Base adapter class for all integrations.

Provides common functionality for authentication, health checks, and error handling.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class IntegrationStatus(str, Enum):
    """Status of an integration connection."""
    NOT_CONFIGURED = "not_configured"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"


@dataclass
class IntegrationConfig:
    """Configuration for an integration."""
    integration_id: str
    name: str
    type: str
    enabled: bool = False
    config: Dict[str, Any] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    last_tested: Optional[str] = None
    last_test_status: Optional[IntegrationStatus] = None
    last_error: Optional[str] = None
    rate_limit_reset: Optional[str] = None

    def get_config(self) -> Dict[str, Any]:
        """Get sanitized configuration dictionary."""
        return {
            "integration_id": self.integration_id,
            "name": self.name,
            "type": self.type,
            "enabled": self.enabled,
            "capabilities": self.capabilities,
            "last_tested": self.last_tested,
            "last_test_status": self.last_test_status.value if self.last_test_status else None,
            "last_error": self.last_error,
            "rate_limit_reset": self.rate_limit_reset,
        }


class IntegrationError(Exception):
    """Base exception for integration errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details or {}


class BaseAdapter(ABC):
    """Base class for all integration adapters.

    All integrations must inherit from this class and implement the required methods.
    """

    def __init__(self, config: IntegrationConfig):
        self.config = config
        self._client: Optional[Any] = None

    @property
    @abstractmethod
    def integration_type(self) -> str:
        """Return the integration type (siem, soar, ticketing, firewall)."""
        pass

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the integration.

        Returns:
            True if connection successful, False otherwise.
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the integration."""
        pass

    @abstractmethod
    def test_connection(self) -> IntegrationStatus:
        """Test the connection to the integration.

        Returns:
            IntegrationStatus indicating the connection state.
        """
        pass

    @abstractmethod
    def send_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Send an alert to the integration.

        Args:
            alert: Alert data dictionary.

        Returns:
            Response from the integration.

        Raises:
            IntegrationError: If sending fails.
        """
        pass

    def is_connected(self) -> bool:
        """Check if the adapter is currently connected."""
        return self._client is not None

    def get_config(self) -> Dict[str, Any]:
        """Get the current configuration (with secrets masked)."""
        return {
            "integration_id": self.config.integration_id,
            "name": self.config.name,
            "type": self.config.type,
            "enabled": self.config.enabled,
            "capabilities": self.config.capabilities,
            "last_tested": self.config.last_tested,
            "last_test_status": self.config.last_test_status.value if self.config.last_test_status else None,
            "last_error": self.config.last_error,
            "rate_limit_reset": self.config.rate_limit_reset,
        }

    def update_config(self, **kwargs: Any) -> None:
        """Update configuration parameters."""
        for key, value in kwargs.items():
            if key in self.config.config:
                self.config.config[key] = value

    def mask_secrets(self, data: Dict[str, Any], secret_keys: List[str]) -> Dict[str, Any]:
        """Mask secret values in configuration data.

        Args:
            data: Data dictionary potentially containing secrets.
            secret_keys: List of keys that should be masked.

        Returns:
            Data with secrets masked.
        """
        masked = data.copy()
        for key in secret_keys:
            if key in masked and masked[key]:
                masked[key] = "********"
        return masked

    def log_error(self, error: Exception, context: Optional[Dict[str, Any]] = None) -> None:
        """Log an error with context.

        Args:
            error: The exception that occurred.
            context: Additional context information.
        """
        error_details = {
            "integration": self.config.integration_id,
            "type": self.integration_type,
            "error": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if context:
            error_details.update(context)
        logger.error(f"Integration error: {json.dumps(error_details)}")

    def handle_rate_limit(self, reset_time: Optional[str] = None) -> None:
        """Handle rate limiting by storing reset time and updating status.

        Args:
            reset_time: ISO timestamp when rate limit resets.
        """
        self.config.last_test_status = IntegrationStatus.RATE_LIMITED
        self.config.rate_limit_reset = reset_time or datetime.now(timezone.utc).isoformat()
        logger.warning(f"Rate limit hit for {self.config.integration_id}, resets at {reset_time}")

    def _now(self) -> str:
        """Get current UTC timestamp as ISO string."""
        return datetime.now(timezone.utc).isoformat()
