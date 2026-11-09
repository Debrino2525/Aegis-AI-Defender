"""Device fingerprinting for passive device type detection."""

from typing import Any, Dict, Optional


class DeviceFingerprinter:
    """Passive device type detection using network data."""

    def __init__(self):
        pass

    def fingerprint_from_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """Identify device type from MAC OUI."""
        if not mac_address:
            return None
        
        oui = mac_address[:8].upper()
        # Simplified OUI mapping - in production would use full database
        oui_map = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:1B:21": "Apple",
            "00:1A:11": "Apple",
            "00:15:5D": "Apple",
            "00:0C:42": "Apple",
            "00:1B:63": "Apple",
            "08:00:27": "Dell",
            "00:14:22": "Dell",
            "00:1E:67": "Dell",
            "00:16:76": "Cisco",
            "00:1B:D5": "Cisco",
            "F0:DB:4E": "Cisco",
            "F4:8C:50": "Cisco",
            "00:0C:29": "HP",
            "00:1F:6C": "HP",
            "3C:97:0E": "HP",
            "00:25:9C": "Intel",
            "00:E0:4C": "Intel",
            "FC:48:3E": "Intel",
        }
        
        vendor = oui_map.get(oui)
        if vendor:
            return {"vendor": vendor, "confidence": "high"}
        return None

    def fingerprint_from_http(self, user_agent: str, server_header: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Identify device type from HTTP data."""
        if not user_agent:
            return None
        
        ua_lower = user_agent.lower()
        
        if "windows" in ua_lower:
            return {"os": "Windows", "type": "desktop", "confidence": "medium"}
        elif "macintosh" in ua_lower or "mac os x" in ua_lower:
            return {"os": "macOS", "type": "desktop", "confidence": "medium"}
        elif "linux" in ua_lower:
            return {"os": "Linux", "type": "server", "confidence": "medium"}
        elif "android" in ua_lower:
            return {"os": "Android", "type": "mobile", "confidence": "high"}
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            return {"os": "iOS", "type": "mobile", "confidence": "high"}
        
        return None

    def fingerprint_from_ssh(self, ssh_banner: str) -> Optional[Dict[str, Any]]:
        """Identify device type from SSH banner."""
        if not ssh_banner:
            return None
        
        banner_lower = ssh_banner.lower()
        
        if "ubuntu" in banner_lower:
            return {"os": "Ubuntu", "type": "server", "confidence": "high"}
        elif "debian" in banner_lower:
            return {"os": "Debian", "type": "server", "confidence": "high"}
        elif "red hat" in banner_lower or "rhel" in banner_lower:
            return {"os": "Red Hat", "type": "server", "confidence": "high"}
        elif "centos" in banner_lower:
            return {"os": "CentOS", "type": "server", "confidence": "high"}
        elif "windows" in banner_lower:
            return {"os": "Windows", "type": "desktop", "confidence": "high"}
        
        return None
