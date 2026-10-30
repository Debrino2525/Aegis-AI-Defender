"""Unified asset posture: enrolled hosts joined with Prevent scan findings."""

from aegis.assets.identity import host_keys, is_unusable_ip, normalize_host, value_hits
from aegis.assets.posture import attach_host_posture, posture_for_keys

__all__ = [
    "attach_host_posture",
    "host_keys",
    "is_unusable_ip",
    "normalize_host",
    "posture_for_keys",
    "value_hits",
]
