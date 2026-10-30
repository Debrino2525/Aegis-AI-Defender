"""Host identity keys used to join fleet rows with scan findings.

Assets and Device investigation must match on the same keys. Nothing here
invents a hostname or address.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Set


def normalize_host(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    if text.endswith("]") and "[" in text:
        text = text.split("[", 1)[1]
    if text.count(":") == 1 and "." in text.split(":", 1)[0]:
        text = text.split(":", 1)[0]
    if "%" in text:
        text = text.split("%", 1)[0]
    return text.strip()


def is_unusable_ip(value: str) -> bool:
    host = normalize_host(value)
    if not host:
        return True
    if host in {"unknown", "multiple", "multiple internal", "external", "localhost"}:
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        addr.is_loopback
        or addr.is_unspecified
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    )


def host_keys(host: dict) -> Set[str]:
    keys: Set[str] = set()
    agent_id = str(host.get("agent_id") or "").strip()
    if agent_id:
        keys.add(agent_id.lower())
    hostname = normalize_host(host.get("hostname"))
    if hostname:
        keys.add(hostname)
    remote = normalize_host(host.get("remote_ip"))
    if remote and not is_unusable_ip(remote):
        keys.add(remote)
    for bucket in ("ipv4", "ipv6"):
        for item in host.get(bucket) or []:
            addr = normalize_host(item)
            if addr and not is_unusable_ip(addr):
                keys.add(addr)
    return keys


def value_hits(value: Any, keys: Set[str]) -> bool:
    host = normalize_host(value)
    if not host:
        return False
    if host in keys:
        return True
    bare = host.split(":")[0]
    return bare in keys
