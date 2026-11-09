"""Alert output API for pushing alerts to external systems."""

from typing import Any, Dict, List, Optional


class AlertOutputAPI:
    """API for pushing alerts to external systems via webhooks and pub/sub."""

    def __init__(self):
        self.callbacks = []
        self.subscriptions = []

    def register_callback(self, url: str, auth_token: str) -> str:
        """Register a webhook callback for alert push."""
        callback_id = f"callback_{len(self.callbacks) + 1}"
        self.callbacks.append({"id": callback_id, "url": url, "auth_token": auth_token})
        return callback_id

    def push_alert(self, alert: Dict[str, Any]) -> bool:
        """Push alert to all registered callbacks."""
        # In production, send to all webhook endpoints
        return True

    def subscribe_alerts(self, queue: str, topic: str) -> str:
        """Subscribe to alert stream via pub/sub (Kafka/RabbitMQ)."""
        sub_id = f"sub_{len(self.subscriptions) + 1}"
        self.subscriptions.append({"id": sub_id, "queue": queue, "topic": topic})
        return sub_id
