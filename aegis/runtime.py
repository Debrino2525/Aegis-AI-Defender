"""Operator runtime paths and the default listen address."""

import os
from pathlib import Path
from typing import Optional


_ALL_INTERFACES = {"0.0.0.0", "::", "[::]"}


def aegis_data_dir() -> Path:
    """Directory for operator state. Defaults to ~/.aegis, never the repo tree."""
    override = os.getenv("AEGIS_DATA_DIR", "").strip()
    path = Path(override).expanduser() if override else Path.home() / ".aegis"
    path.mkdir(parents=True, exist_ok=True)
    return path


def listen_host() -> str:
    """Bind address. Loopback unless AEGIS_HOST explicitly says otherwise."""
    return os.getenv("AEGIS_HOST", "127.0.0.1").strip() or "127.0.0.1"


def listen_port() -> int:
    raw = os.getenv("AEGIS_PORT", "8000").strip() or "8000"
    return int(raw)


def all_interfaces_warning(host: str) -> Optional[str]:
    """Loud warning when the process is configured to listen beyond localhost."""
    if host not in _ALL_INTERFACES:
        return None
    return (
        "[AEGIS] WARNING: AEGIS_HOST is "
        f"{host}, so the console listens on all interfaces. "
        "Authentication is required, but anyone who can route to this machine can reach the port. "
        "Prefer 127.0.0.1 unless you explicitly intend to expose the console."
    )
