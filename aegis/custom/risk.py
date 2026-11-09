"""Business risk tailoring engine."""

from typing import Any, Dict, List, Optional


class BusinessRiskEngine:
    """Engine for business risk tailoring and asset criticality."""

    def __init__(self):
        self.vip_assets = []
        self.risk_framework = "NIST"

    def set_risk_framework(self, framework: str) -> None:
        """Set risk framework (NIST, ISO 27001, CIS)."""
        self.risk_framework = framework

    def add_vip_asset(self, asset_id: str, criticality: str = "high") -> bool:
        """Add VIP asset with criticality level."""
        if not any(a["id"] == asset_id for a in self.vip_assets):
            self.vip_assets.append({"id": asset_id, "criticality": criticality})
            return True
        return False

    def get_vip_assets(self) -> List[Dict[str, Any]]:
        """Get all VIP assets."""
        return self.vip_assets

    def calculate_risk(self, asset_id: str, base_score: float) -> float:
        """Calculate adjusted risk score based on asset criticality."""
        for asset in self.vip_assets:
            if asset["id"] == asset_id:
                if asset["criticality"] == "high":
                    return base_score * 1.5
                elif asset["criticality"] == "medium":
                    return base_score * 1.2
        return base_score
