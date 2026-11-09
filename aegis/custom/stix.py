"""STIX/TAXII threat intelligence merging."""

from typing import Any, Dict, List, Optional


class STIXManager:
    """Manager for STIX/TAXII threat intelligence feeds."""

    def __init__(self):
        self.feeds = []
        self.iocs = []

    def add_stix_feed(self, url: str, api_key: Optional[str] = None) -> str:
        """Add a STIX/TAXII feed."""
        feed_id = f"stix_{len(self.feeds) + 1}"
        self.feeds.append({"id": feed_id, "url": url, "api_key": api_key})
        return feed_id

    def get_feeds(self) -> List[Dict[str, Any]]:
        """Get all STIX feeds."""
        return self.feeds

    def sync_feed(self, feed_id: str) -> List[Dict[str, Any]]:
        """Sync indicators from a STIX feed."""
        # In production, fetch STIX data from TAXII server
        return []

    def merge_iocs(self, new_iocs: List[Dict[str, Any]]) -> int:
        """Merge new IOCs with existing threat intelligence."""
        count = 0
        for ioc in new_iocs:
            if not any(i["value"] == ioc["value"] for i in self.iocs):
                self.iocs.append(ioc)
                count += 1
        return count
