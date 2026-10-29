"""
Aegis AI — Base Alert Adapter Interface.
"""

from abc import ABC, abstractmethod
from aegis.alerting.models import CriticalAlert, OnCallContact, DispatchResult


class BaseAlertAdapter(ABC):
    """Abstract interface for all notification channel transport adapters."""

    @property
    @abstractmethod
    def channel_name(self) -> str:
        """Name identifier of the channel (e.g. 'sms_local', 'telegram', 'whatsapp')."""
        pass

    @abstractmethod
    async def send(self, alert: CriticalAlert, contact: OnCallContact, triage_url: str) -> DispatchResult:
        """
        Dispatches an alert through the transport medium.
        Returns a structured DispatchResult indicating success, latency, and references.
        """
        pass
