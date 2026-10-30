"""Host inventory for a heartbeat. Counts and listen ports — not a packet tap."""

from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aegis import __version__ as AGENT_VERSION

_LINK_LOCAL_V4_PREFIX = "169.254."
_LOOPBACK = {"127.0.0.1", "::1", "0.0.0.0", "::"}
# RDP / SMB / SSH only — hop evidence for Analyst Assist, not a packet tap.
_HOP_PORTS = {22, 139, 445, 3389}


def collect_telemetry() -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_version": platform.release(),
        "arch": platform.machine(),
        "agent_version": AGENT_VERSION,
        "ipv4": [],
        "ipv6": [],
        "listening_tcp": [],
        "listen_count": 0,
        "established_in": 0,
        "established_out": 0,
        "hop_connections": [],
        "connection_count": 0,
        "process_count": None,
        "cpu_percent": None,
        "memory_percent": None,
        "boot_time": None,
        "uptime_seconds": None,
        "telemetry_errors": [],
    }
    _fill_addresses(payload)
    _fill_psutil(payload)
    return payload


def _fill_addresses(payload: Dict[str, Any]) -> None:
    ipv4: List[str] = []
    ipv6: List[str] = []
    try:
        import psutil
        for _iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                ip = getattr(addr, "address", "") or ""
                ip = ip.split("%", 1)[0]
                if not ip or ip in _LOOPBACK:
                    continue
                if ":" in ip:
                    if ip.lower().startswith("fe80"):
                        continue
                    if ip not in ipv6:
                        ipv6.append(ip)
                else:
                    if ip.startswith(_LINK_LOCAL_V4_PREFIX):
                        continue
                    if ip not in ipv4:
                        ipv4.append(ip)
    except Exception as exc:
        payload["telemetry_errors"].append(f"net_if_addrs: {exc}")
        try:
            host = socket.gethostname()
            for info in socket.getaddrinfo(host, None):
                ip = info[4][0]
                if ip in _LOOPBACK:
                    continue
                if ":" in ip and ip not in ipv6 and not ip.lower().startswith("fe80"):
                    ipv6.append(ip)
                elif ":" not in ip and ip not in ipv4 and not ip.startswith(_LINK_LOCAL_V4_PREFIX):
                    ipv4.append(ip)
        except Exception as inner:
            payload["telemetry_errors"].append(f"getaddrinfo: {inner}")
    payload["ipv4"] = ipv4[:16]
    payload["ipv6"] = ipv6[:16]


def _fill_psutil(payload: Dict[str, Any]) -> None:
    try:
        import psutil
    except Exception as exc:
        payload["telemetry_errors"].append(f"psutil: {exc}")
        return
    try:
        payload["process_count"] = len(psutil.pids())
    except Exception as exc:
        payload["telemetry_errors"].append(f"process_count: {exc}")
    try:
        payload["cpu_percent"] = float(psutil.cpu_percent(interval=None))
    except Exception as exc:
        payload["telemetry_errors"].append(f"cpu_percent: {exc}")
    try:
        payload["memory_percent"] = float(psutil.virtual_memory().percent)
    except Exception as exc:
        payload["telemetry_errors"].append(f"memory_percent: {exc}")
    try:
        boot = float(psutil.boot_time())
        payload["boot_time"] = datetime.fromtimestamp(boot, tz=timezone.utc).isoformat()
        payload["uptime_seconds"] = int(max(0, datetime.now(timezone.utc).timestamp() - boot))
    except Exception as exc:
        payload["telemetry_errors"].append(f"boot_time: {exc}")
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as exc:
        payload["telemetry_errors"].append(f"net_connections: {exc}")
        return
    listening = []
    hop_connections = []
    established_in = 0
    established_out = 0
    for conn in conns:
        status = getattr(conn, "status", "") or ""
        laddr = getattr(conn, "laddr", None)
        raddr = getattr(conn, "raddr", None)
        if status == "LISTEN" and laddr:
            ip = getattr(laddr, "ip", "") or ""
            port = getattr(laddr, "port", None)
            listening.append({"ip": ip, "port": port})
        elif status == "ESTABLISHED":
            lip = getattr(laddr, "ip", "") if laddr else ""
            rip = getattr(raddr, "ip", "") if raddr else ""
            lport = getattr(laddr, "port", None) if laddr else None
            rport = getattr(raddr, "port", None) if raddr else None
            if lip in _LOOPBACK or (isinstance(lip, str) and lip.startswith("127.")):
                established_in += 1
            else:
                established_out += 1
            hop = _hop_connection(lip, lport, rip, rport)
            if hop:
                hop_connections.append(hop)
    payload["listening_tcp"] = listening[:64]
    payload["listen_count"] = len(listening)
    payload["established_in"] = established_in
    payload["established_out"] = established_out
    payload["hop_connections"] = hop_connections[:32]
    payload["connection_count"] = len(conns)


def _hop_connection(lip: str, lport: Any, rip: str, rport: Any) -> Optional[Dict[str, Any]]:
    """One ESTABLISHED RDP/SMB/SSH edge this agent can see. Empty if not a hop port."""
    lip = (lip or "").split("%", 1)[0]
    rip = (rip or "").split("%", 1)[0]
    if not lip or not rip:
        return None
    if lip in _LOOPBACK or rip in _LOOPBACK:
        return None
    if isinstance(lip, str) and lip.startswith("127."):
        return None
    if isinstance(rip, str) and rip.startswith("127."):
        return None
    try:
        remote_port = int(rport) if rport is not None else None
    except (TypeError, ValueError):
        remote_port = None
    try:
        local_port = int(lport) if lport is not None else None
    except (TypeError, ValueError):
        local_port = None
    if remote_port in _HOP_PORTS:
        return {
            "local_ip": lip,
            "remote_ip": rip,
            "remote_port": remote_port,
            "local_port": local_port,
            "status": "ESTABLISHED",
        }
    if local_port in _HOP_PORTS:
        return {
            "local_ip": rip,
            "remote_ip": lip,
            "remote_port": local_port,
            "local_port": remote_port,
            "status": "ESTABLISHED",
        }
    return None
