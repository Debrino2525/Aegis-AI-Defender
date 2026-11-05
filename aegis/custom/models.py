"""Custom threat model management."""

from typing import Any, Dict, List, Optional


class CustomModelManager:
    """Manager for custom threat detection models."""

    def __init__(self):
        self.models = []

    def create_model(self, name: str, pattern: str, severity: str = "medium") -> str:
        """Create a custom threat detection model."""
        model_id = f"custom_{len(self.models) + 1}"
        self.models.append({"id": model_id, "name": name, "pattern": pattern, "severity": severity})
        return model_id

    def get_models(self) -> List[Dict[str, Any]]:
        """Get all custom models."""
        return self.models

    def update_model(self, model_id: str, pattern: str) -> bool:
        """Update a custom model."""
        for model in self.models:
            if model["id"] == model_id:
                model["pattern"] = pattern
                return True
        return False

    def delete_model(self, model_id: str) -> bool:
        """Delete a custom model."""
        self.models = [m for m in self.models if m["id"] != model_id]
        return True
