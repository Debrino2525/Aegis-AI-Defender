"""Local MaxMind GeoLite2 City lookups.

Coordinates come only from a database file named by ``GEOIP_DB_PATH``.
A missing file, a private address, or an unknown address yields no point.
Nothing in this module calls a GeoIP web API.
"""

from __future__ import annotations

import ipaddress
import os
import threading
from typing import Any, Dict, Iterable, Optional


def public_ip(value: Any) -> Optional[str]:
    """Return a global address, or None for private, local, and unparsable input."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"external", "unknown", "localhost"}:
        return None
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if not addr.is_global:
        return None
    return str(addr)


class GeoIPLookup:
    """Reads one local GeoLite2-City.mmdb. Safe to call when the file is absent."""

    def __init__(self, path: Optional[str] = None, reader: Any = None) -> None:
        self._lock = threading.Lock()
        self._reader = None
        self._owns_reader = False
        self.path = ""
        self.database = "missing"
        if reader is not None:
            self._reader = reader
            self._owns_reader = False
            self.database = "loaded"
            self.path = path or ""
            return
        self.reload(path)

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()

    def _close_unlocked(self) -> None:
        reader = self._reader
        self._reader = None
        if reader is not None and self._owns_reader:
            try:
                reader.close()
            except Exception:
                pass
        self._owns_reader = False

    def reload(self, path: Optional[str] = None) -> None:
        chosen = os.getenv("GEOIP_DB_PATH", "") if path is None else path
        chosen = str(chosen or "").strip()
        with self._lock:
            self._close_unlocked()
            self.path = chosen
            self.database = "missing"
            if not chosen or not os.path.isfile(chosen):
                return
            try:
                from geoip2.database import Reader
                self._reader = Reader(chosen)
                self._owns_reader = True
                self.database = "loaded"
            except Exception:
                self._reader = None
                self._owns_reader = False
                self.database = "missing"

    @property
    def configured(self) -> bool:
        return self._reader is not None and self.database == "loaded"

    def lookup(self, ip: Any, reader: Any = None) -> Optional[Dict[str, Any]]:
        """Return lat/lon from the database, or None. Never invents a coordinate."""
        public = public_ip(ip)
        if public is None:
            return None
        active = reader if reader is not None else self._reader
        if active is None:
            return None
        try:
            record = active.city(public)
        except Exception:
            return None
        location = getattr(record, "location", None)
        if location is None:
            return None
        lat = getattr(location, "latitude", None)
        lon = getattr(location, "longitude", None)
        if lat is None or lon is None:
            return None
        try:
            latitude = float(lat)
            longitude = float(lon)
        except (TypeError, ValueError):
            return None
        if not (-90.0 <= latitude <= 90.0 and -180.0 <= longitude <= 180.0):
            return None
        # MaxMind leaves 0,0 when a network has no location.
        if latitude == 0.0 and longitude == 0.0:
            return None
        city_obj = getattr(record, "city", None)
        country_obj = getattr(record, "country", None)
        city = getattr(city_obj, "name", None) or ""
        country = getattr(country_obj, "iso_code", None) or ""
        return {
            "ip": public,
            "latitude": latitude,
            "longitude": longitude,
            "city": str(city),
            "country": str(country),
        }

    def snapshot(self, ips: Iterable[Any]) -> Dict[str, Any]:
        points = []
        seen = set()
        for raw in ips:
            hit = self.lookup(raw)
            if not hit or hit["ip"] in seen:
                continue
            seen.add(hit["ip"])
            points.append(hit)
            if len(points) >= 40:
                break
        return {
            "configured": self.configured,
            "database": "loaded" if self.configured else "missing",
            "points": points,
        }


_service: Optional[GeoIPLookup] = None
_service_lock = threading.Lock()


def service() -> GeoIPLookup:
    global _service
    with _service_lock:
        if _service is None:
            _service = GeoIPLookup()
        return _service


def reload_geoip() -> GeoIPLookup:
    global _service
    with _service_lock:
        if _service is None:
            _service = GeoIPLookup()
        else:
            _service.reload()
        return _service


def lookup_ip(ip: Any) -> Optional[Dict[str, Any]]:
    return service().lookup(ip)


def geoip_snapshot(ips: Iterable[Any]) -> Dict[str, Any]:
    return service().snapshot(ips)


def collect_monitor_ips(connections: Iterable[Dict[str, Any]], nodes: Iterable[Dict[str, Any]] = ()) -> list:
    """Public remotes from live sockets on this host.

    Graph leftovers and well-known web-edge ranges are omitted so the threat
    map cannot keep a globe of CDN or hashed-IP dots after a reset. Private
    addresses are dropped later by ``lookup``. ``nodes`` is ignored.
    """
    from aegis.monitor.threat_patterns import is_well_known_web_edge

    found = []
    for conn in connections or []:
        remote = conn.get("remote_ip")
        if not remote:
            continue
        if is_well_known_web_edge(str(remote)):
            continue
        found.append(remote)
    return found
