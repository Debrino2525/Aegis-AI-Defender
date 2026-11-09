"""Device fingerprinting for enhanced asset identification.

Collects OS, service, and hardware information from agents and scans
to create rich device profiles for asset management.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from enum import Enum


class OSType(Enum):
    """Operating system types."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    BSD = "bsd"
    UNKNOWN = "unknown"


class DeviceRole(Enum):
    """Device roles in the network."""
    WORKSTATION = "workstation"
    SERVER = "server"
    NETWORK_DEVICE = "network_device"
    IOT = "iot"
    UNKNOWN = "unknown"


@dataclass
class DeviceFingerprint:
    """Complete device fingerprint."""
    device_id: str
    hostname: str
    os_type: OSType = OSType.UNKNOWN
    os_version: Optional[str] = None
    os_release: Optional[str] = None
    architecture: Optional[str] = None
    cpu_count: Optional[int] = None
    total_memory: Optional[int] = None
    disk_info: List[Dict[str, Any]] = field(default_factory=list)
    network_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    role: DeviceRole = DeviceRole.UNKNOWN
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "os_type": self.os_type.value,
            "os_version": self.os_version,
            "os_release": self.os_release,
            "architecture": self.architecture,
            "cpu_count": self.cpu_count,
            "total_memory": self.total_memory,
            "disk_info": self.disk_info,
            "network_interfaces": self.network_interfaces,
            "services": self.services,
            "role": self.role.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceFingerprint":
        """Create from dictionary."""
        return cls(
            device_id=data["device_id"],
            hostname=data["hostname"],
            os_type=OSType(data.get("os_type", "unknown")),
            os_version=data.get("os_version"),
            os_release=data.get("os_release"),
            architecture=data.get("architecture"),
            cpu_count=data.get("cpu_count"),
            total_memory=data.get("total_memory"),
            disk_info=data.get("disk_info", []),
            network_interfaces=data.get("network_interfaces", []),
            services=data.get("services", []),
            role=DeviceRole(data.get("role", "unknown")),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            metadata=data.get("metadata", {}),
        )


class DeviceFingerprinter:
    """Analyzes agent telemetry and scan data to build device fingerprints."""

    def __init__(self):
        self._fingerprints: Dict[str, DeviceFingerprint] = {}

    def fingerprint_from_agent(self, agent_data: Dict[str, Any]) -> DeviceFingerprint:
        """Build fingerprint from agent heartbeat data."""
        device_id = agent_data.get("agent_id") or agent_data.get("hostname") or "unknown"
        hostname = agent_data.get("hostname") or "unknown"

        fp = DeviceFingerprint(
            device_id=device_id,
            hostname=hostname,
        )

        # OS detection
        os_info = agent_data.get("os_info", {})
        fp.os_type = self._detect_os_type(os_info)
        fp.os_version = os_info.get("version")
        fp.os_release = os_info.get("release")
        fp.architecture = os_info.get("architecture")

        # Hardware info
        hw_info = agent_data.get("hardware", {})
        fp.cpu_count = hw_info.get("cpu_count")
        fp.total_memory = hw_info.get("total_memory")
        fp.disk_info = hw_info.get("disks", [])

        # Network interfaces
        fp.network_interfaces = agent_data.get("network_interfaces", [])

        # Services from agent
        fp.services = agent_data.get("services", [])

        # Detect role
        fp.role = self._detect_role(fp)

        # Update last seen
        fp.last_seen = datetime.now(timezone.utc).isoformat()

        return fp

    def fingerprint_from_scan(self, scan_data: Dict[str, Any]) -> Optional[DeviceFingerprint]:
        """Build fingerprint from scan results (for unmanaged assets)."""
        target = scan_data.get("target") or scan_data.get("host")
        if not target:
            return None

        device_id = f"scan:{target}"
        hostname = target

        fp = DeviceFingerprint(
            device_id=device_id,
            hostname=hostname,
        )

        # Extract services from scan
        services = scan_data.get("services", [])
        fp.services = services

        # Detect OS from service banners
        fp.os_type = self._infer_os_from_services(services)
        fp.role = self._detect_role_from_services(services)

        # Network info from scan
        scan_ports = scan_data.get("open_ports", [])
        if scan_ports:
            fp.network_interfaces = [{"addresses": [target], "open_ports": scan_ports}]

        return fp

    def merge_fingerprints(self, existing: DeviceFingerprint, new: DeviceFingerprint) -> DeviceFingerprint:
        """Merge new fingerprint data into existing."""
        if existing.device_id != new.device_id:
            return existing

        # Update last seen
        existing.last_seen = new.last_seen

        # Merge OS info if new has more data
        if new.os_type != OSType.UNKNOWN and existing.os_type == OSType.UNKNOWN:
            existing.os_type = new.os_type
        if new.os_version and not existing.os_version:
            existing.os_version = new.os_version
        if new.os_release and not existing.os_release:
            existing.os_release = new.os_release
        if new.architecture and not existing.architecture:
            existing.architecture = new.architecture

        # Merge hardware info
        if new.cpu_count and not existing.cpu_count:
            existing.cpu_count = new.cpu_count
        if new.total_memory and not existing.total_memory:
            existing.total_memory = new.total_memory
        if new.disk_info and not existing.disk_info:
            existing.disk_info = new.disk_info

        # Merge network interfaces
        existing.network_interfaces = self._merge_network_interfaces(
            existing.network_interfaces, new.network_interfaces
        )

        # Merge services
        existing.services = self._merge_services(existing.services, new.services)

        # Update role if better detected
        if new.role != DeviceRole.UNKNOWN and existing.role == DeviceRole.UNKNOWN:
            existing.role = new.role

        return existing

    def update_fingerprint(self, fp: DeviceFingerprint) -> None:
        """Store or update a fingerprint."""
        if fp.device_id in self._fingerprints:
            self._fingerprints[fp.device_id] = self.merge_fingerprints(
                self._fingerprints[fp.device_id], fp
            )
        else:
            self._fingerprints[fp.device_id] = fp

    def get_fingerprint(self, device_id: str) -> Optional[DeviceFingerprint]:
        """Get a stored fingerprint."""
        return self._fingerprints.get(device_id)

    def list_fingerprints(self) -> List[DeviceFingerprint]:
        """List all stored fingerprints."""
        return list(self._fingerprints.values())

    def _detect_os_type(self, os_info: Dict[str, Any]) -> OSType:
        """Detect OS type from agent data."""
        os_name = (os_info.get("name") or os_info.get("system") or "").lower()
        if "windows" in os_name:
            return OSType.WINDOWS
        elif "linux" in os_name:
            return OSType.LINUX
        elif "darwin" in os_name or "mac" in os_name:
            return OSType.MACOS
        elif "bsd" in os_name:
            return OSType.BSD
        return OSType.UNKNOWN

    def _infer_os_from_services(self, services: List[Dict[str, Any]]) -> OSType:
        """Infer OS from detected services."""
        for svc in services:
            product = (svc.get("product") or "").lower()
            banner = (svc.get("banner") or "").lower()
            service_name = (svc.get("service_name") or "").lower()

            # Windows indicators
            if "microsoft" in product or "iis" in product or "windows" in banner:
                return OSType.WINDOWS
            if service_name == "microsoft-ds" or service_name == "netbios":
                return OSType.WINDOWS

            # Linux indicators
            if "openssh" in product or "apache" in product or "nginx" in product:
                return OSType.LINUX
            if "ubuntu" in banner or "debian" in banner or "centos" in banner:
                return OSType.LINUX

        return OSType.UNKNOWN

    def _detect_role(self, fp: DeviceFingerprint) -> DeviceRole:
        """Detect device role from fingerprint."""
        # Server indicators
        server_services = {"http", "https", "mysql", "postgresql", "redis", "mongodb", "smtp", "dns"}
        service_names = {s.get("service_name", "").lower() for s in fp.services}

        if server_services.intersection(service_names):
            return DeviceRole.SERVER

        # Network device indicators
        if any(s.get("service_name") in ["snmp", "router", "switch"] for s in fp.services):
            return DeviceRole.NETWORK_DEVICE

        # IoT indicators
        if fp.os_type == OSType.LINUX and fp.cpu_count and fp.cpu_count < 4:
            if fp.total_memory and fp.total_memory < 4 * 1024 * 1024 * 1024:  # < 4GB
                return DeviceRole.IOT

        return DeviceRole.WORKSTATION

    def _detect_role_from_services(self, services: List[Dict[str, Any]]) -> DeviceRole:
        """Detect role from scan services only."""
        server_services = {"http", "https", "mysql", "postgresql", "redis", "mongodb", "smtp", "dns"}
        service_names = {s.get("service_name", "").lower() for s in services}

        if server_services.intersection(service_names):
            return DeviceRole.SERVER

        return DeviceRole.UNKNOWN

    def _merge_network_interfaces(
        self, existing: List[Dict[str, Any]], new: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Merge network interface data."""
        seen = set()
        merged = []

        for iface in existing + new:
            for addr in iface.get("addresses", []):
                if addr not in seen:
                    seen.add(addr)
                    merged.append(iface)
                    break

        return merged

    def _merge_services(self, existing: List[Dict[str, Any]], new: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge service lists, avoiding duplicates."""
        seen = set()
        merged = []

        for svc in existing + new:
            key = (svc.get("port"), svc.get("service_name"), svc.get("protocol"))
            if key not in seen:
                seen.add(key)
                merged.append(svc)

        return merged


# Global instance
_fingerprinter: Optional[DeviceFingerprinter] = None


def get_device_fingerprinter() -> DeviceFingerprinter:
    """Get the global device fingerprinter instance."""
    global _fingerprinter
    if _fingerprinter is None:
        _fingerprinter = DeviceFingerprinter()
    return _fingerprinter
