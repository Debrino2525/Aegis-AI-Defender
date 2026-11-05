"""Asset lifecycle tracking and inventory management.

Manages the complete lifecycle of assets from discovery to decommission,
including change tracking, risk scoring, and inventory history.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from enum import Enum

from aegis.assets.fingerprint import DeviceFingerprint, DeviceRole, OSType


class AssetStatus(Enum):
    """Asset lifecycle status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    QUARANTINED = "quarantined"
    UNKNOWN = "unknown"


class AssetRiskLevel(Enum):
    """Asset risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class AssetChangeEvent:
    """Represents a change to an asset."""
    timestamp: str
    change_type: str  # "created", "updated", "deleted", "status_changed", "risk_changed"
    field: str
    old_value: Any
    new_value: Any
    source: str  # "agent", "scan", "manual"
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "change_type": self.change_type,
            "field": self.field,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "source": self.source,
            "description": self.description,
        }


@dataclass
class Asset:
    """Complete asset record with lifecycle tracking."""
    asset_id: str
    hostname: str
    status: AssetStatus = AssetStatus.UNKNOWN
    risk_level: AssetRiskLevel = AssetRiskLevel.UNKNOWN
    fingerprint: Optional[DeviceFingerprint] = None
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    change_history: List[AssetChangeEvent] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    notes: str = ""
    owner: Optional[str] = None
    location: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "change_history": [c.to_dict() for c in self.change_history],
            "tags": list(self.tags),
            "notes": self.notes,
            "owner": self.owner,
            "location": self.location,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Asset":
        """Create from dictionary."""
        fp_data = data.get("fingerprint")
        fingerprint = DeviceFingerprint.from_dict(fp_data) if fp_data else None

        return cls(
            asset_id=data["asset_id"],
            hostname=data["hostname"],
            status=AssetStatus(data.get("status", "unknown")),
            risk_level=AssetRiskLevel(data.get("risk_level", "unknown")),
            fingerprint=fingerprint,
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            change_history=[
                AssetChangeEvent(**c) for c in data.get("change_history", [])
            ],
            tags=set(data.get("tags", [])),
            notes=data.get("notes", ""),
            owner=data.get("owner"),
            location=data.get("location"),
            metadata=data.get("metadata", {}),
        )

    def add_change(self, change: AssetChangeEvent) -> None:
        """Add a change event to history."""
        self.change_history.append(change)
        # Keep only last 100 changes
        if len(self.change_history) > 100:
            self.change_history = self.change_history[-100:]

    def update_status(self, new_status: AssetStatus, source: str = "manual") -> None:
        """Update asset status with change tracking."""
        if self.status != new_status:
            change = AssetChangeEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                change_type="status_changed",
                field="status",
                old_value=self.status.value,
                new_value=new_status.value,
                source=source,
                description=f"Status changed from {self.status.value} to {new_status.value}",
            )
            self.add_change(change)
            self.status = new_status

    def update_risk(self, new_risk: AssetRiskLevel, source: str = "auto") -> None:
        """Update asset risk level with change tracking."""
        if self.risk_level != new_risk:
            change = AssetChangeEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                change_type="risk_changed",
                field="risk_level",
                old_value=self.risk_level.value,
                new_value=new_risk.value,
                source=source,
                description=f"Risk level changed from {self.risk_level.value} to {new_risk.value}",
            )
            self.add_change(change)
            self.risk_level = new_risk

    def add_tag(self, tag: str) -> None:
        """Add a tag to the asset."""
        if tag and tag not in self.tags:
            self.tags.add(tag)

    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the asset."""
        self.tags.discard(tag)


class AssetInventory:
    """Manages the complete asset inventory with lifecycle tracking."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path.home() / ".aegis" / "inventory.sqlite3"
        self._assets: Dict[str, Asset] = {}
        self._load_inventory()

    def _load_inventory(self) -> None:
        """Load inventory from storage."""
        if self.db_path.exists():
            try:
                with open(self.db_path, "r") as f:
                    data = json.load(f)
                    for asset_id, asset_data in data.items():
                        self._assets[asset_id] = Asset.from_dict(asset_data)
            except Exception as e:
                print(f"Failed to load inventory: {e}")

    def _save_inventory(self) -> None:
        """Save inventory to storage."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            data = {aid: asset.to_dict() for aid, asset in self._assets.items()}
            with open(self.db_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Failed to save inventory: {e}")

    def create_asset(
        self,
        asset_id: str,
        hostname: str,
        fingerprint: Optional[DeviceFingerprint] = None,
        source: str = "manual",
    ) -> Asset:
        """Create a new asset."""
        if asset_id in self._assets:
            return self._assets[asset_id]

        asset = Asset(
            asset_id=asset_id,
            hostname=hostname,
            fingerprint=fingerprint,
        )

        # Record creation
        change = AssetChangeEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            change_type="created",
            field="asset",
            old_value=None,
            new_value=asset_id,
            source=source,
            description=f"Asset created from {source}",
        )
        asset.add_change(change)

        self._assets[asset_id] = asset
        self._save_inventory()
        return asset

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Get an asset by ID."""
        return self._assets.get(asset_id)

    def update_asset(
        self,
        asset_id: str,
        fingerprint: DeviceFingerprint,
        source: str = "agent",
    ) -> Optional[Asset]:
        """Update an asset with new fingerprint data."""
        asset = self._assets.get(asset_id)
        if not asset:
            return None

        old_fp = asset.fingerprint
        asset.fingerprint = fingerprint
        asset.last_seen = datetime.now(timezone.utc).isoformat()

        # Record update
        change = AssetChangeEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            change_type="updated",
            field="fingerprint",
            old_value=old_fp.to_dict() if old_fp else None,
            new_value=fingerprint.to_dict(),
            source=source,
            description=f"Fingerprint updated from {source}",
        )
        asset.add_change(change)

        self._save_inventory()
        return asset

    def delete_asset(self, asset_id: str, source: str = "manual") -> bool:
        """Delete an asset (marks as decommissioned)."""
        asset = self._assets.get(asset_id)
        if not asset:
            return False

        asset.update_status(AssetStatus.DECOMMISSIONED, source)
        self._save_inventory()
        return True

    def list_assets(
        self,
        status: Optional[AssetStatus] = None,
        risk_level: Optional[AssetRiskLevel] = None,
        tags: Optional[Set[str]] = None,
    ) -> List[Asset]:
        """List assets with optional filters."""
        assets = list(self._assets.values())

        if status:
            assets = [a for a in assets if a.status == status]

        if risk_level:
            assets = [a for a in assets if a.risk_level == risk_level]

        if tags:
            assets = [a for a in assets if tags.issubset(a.tags)]

        return assets

    def calculate_risk_score(self, asset: Asset) -> AssetRiskLevel:
        """Calculate risk level based on asset properties."""
        if not asset.fingerprint:
            return AssetRiskLevel.UNKNOWN

        risk_factors = 0

        # High-risk factors
        if asset.fingerprint.role == DeviceRole.SERVER:
            risk_factors += 2
        if asset.fingerprint.os_type == OSType.WINDOWS:
            risk_factors += 1

        # Check for high-risk services
        high_risk_services = {"radmin", "telnet", "ftp", "tftp"}
        for svc in asset.fingerprint.services:
            if svc.get("service_name", "").lower() in high_risk_services:
                risk_factors += 2

        # Check for open services count
        if len(asset.fingerprint.services) > 10:
            risk_factors += 1

        # Determine risk level
        if risk_factors >= 4:
            return AssetRiskLevel.CRITICAL
        elif risk_factors >= 3:
            return AssetRiskLevel.HIGH
        elif risk_factors >= 1:
            return AssetRiskLevel.MEDIUM
        else:
            return AssetRiskLevel.LOW

    def update_all_risks(self) -> None:
        """Recalculate risk levels for all assets."""
        for asset in self._assets.values():
            new_risk = self.calculate_risk_score(asset)
            asset.update_risk(new_risk, source="auto")
        self._save_inventory()

    def search_assets(self, query: str) -> List[Asset]:
        """Search assets by hostname, tags, or notes."""
        query = query.lower()
        results = []

        for asset in self._assets.values():
            if query in asset.hostname.lower():
                results.append(asset)
                continue
            if any(query in tag.lower() for tag in asset.tags):
                results.append(asset)
                continue
            if query in asset.notes.lower():
                results.append(asset)
                continue

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get inventory statistics."""
        assets = list(self._assets.values())

        return {
            "total_assets": len(assets),
            "by_status": {
                status.value: sum(1 for a in assets if a.status == status)
                for status in AssetStatus
            },
            "by_risk": {
                risk.value: sum(1 for a in assets if a.risk_level == risk)
                for risk in AssetRiskLevel
            },
            "by_os": {
                os_type.value: sum(
                    1 for a in assets
                    if a.fingerprint and a.fingerprint.os_type == os_type
                )
                for os_type in OSType
            },
            "by_role": {
                role.value: sum(
                    1 for a in assets
                    if a.fingerprint and a.fingerprint.role == role
                )
                for role in DeviceRole
            },
        }


# Global instance
_inventory: Optional[AssetInventory] = None


def get_asset_inventory() -> AssetInventory:
    """Get the global asset inventory instance."""
    global _inventory
    if _inventory is None:
        _inventory = AssetInventory()
    return _inventory
