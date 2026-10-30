#!/usr/bin/env python3
"""Part 2F: scan_udp against a local UDP echo server; whether ScanEngine.run calls it."""
import asyncio
import inspect
import json
import socket
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "05_udp.json"

from aegis.core.config import ScanConfig
from aegis.core.engine import ScanEngine
from aegis.discovery.port_scanner import AsyncPortScanner


def start_echo(bind_ip: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, port))
    sock.settimeout(0.5)
    return sock


async def echo_loop(sock, stop_event):
    loop = asyncio.get_event_loop()
    while not stop_event.is_set():
        try:
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), timeout=0.3)
            await loop.sock_sendto(sock, data, addr)
        except Exception:
            await asyncio.sleep(0.05)


async def try_scan(host, port, timeout):
    cfg = ScanConfig(target=host, ports=[port], connect_timeout=timeout)
    scanner = AsyncPortScanner(cfg)
    t0 = asyncio.get_event_loop().time()
    try:
        result = await asyncio.wait_for(scanner.scan_udp(host, [port]), timeout=timeout + 5)
        err = None
    except Exception:
        result = None
        err = traceback.format_exc()
    dt = asyncio.get_event_loop().time() - t0
    return {"result": result, "error": err, "elapsed_s": dt}


async def probe_one(host, port, timeout):
    cfg = ScanConfig(target=host, ports=[port], connect_timeout=timeout)
    scanner = AsyncPortScanner(cfg)
    t0 = asyncio.get_event_loop().time()
    try:
        result = await asyncio.wait_for(scanner._probe_udp_port(host, port), timeout=timeout + 5)
        err = None
    except Exception:
        result = None
        err = traceback.format_exc()
    dt = asyncio.get_event_loop().time() - t0
    return {"result": result, "error": err, "elapsed_s": dt}


async def main():
    bind_ip = "127.0.0.1"
    port = 18053
    sock = start_echo(bind_ip, port)
    # sock_recvfrom requires non-blocking
    sock.setblocking(False)
    stop = asyncio.Event()
    task = asyncio.create_task(echo_loop(sock, stop))
    await asyncio.sleep(0.2)

    blocking_note = {
        "settimeout_called": True,
        "sock_sendto_requires_nonblocking": "asyncio docs: sock must be non-blocking",
        "source_settimeout_line": "aegis/discovery/port_scanner.py:38",
        "source_sock_sendto_line": "aegis/discovery/port_scanner.py:41",
    }

    scan_res = await try_scan(bind_ip, port, timeout=2.0)
    probe_res = await probe_one(bind_ip, port, timeout=2.0)

    # Does ScanEngine.run call scan_udp?
    src = inspect.getsource(ScanEngine.run)
    scan_target_src = inspect.getsource(AsyncPortScanner.scan_target)

    stop.set()
    task.cancel()
    sock.close()

    payload = {
        "blocking_note": blocking_note,
        "scan_udp_against_echo": scan_res,
        "probe_udp_port_against_echo": probe_res,
        "ScanEngine.run_contains_scan_udp": "scan_udp" in src,
        "ScanEngine.run_contains_scan_target": "scan_target" in src,
        "scan_target_scan_udp_param_used": "scan_udp" in scan_target_src and "if scan_udp" in scan_target_src,
        "scan_target_body_uses_udp_flag": "scan_udp" in scan_target_src.split("->")[-1] if False else (
            "if scan_udp" in scan_target_src or "scan_udp:" in scan_target_src
        ),
        "scan_target_source_excerpt": scan_target_src,
        "engine_run_udp_mentions": [line.strip() for line in src.splitlines() if "udp" in line.lower() or "scan_udp" in line],
    }
    OUT.write_text(json.dumps(payload, indent=2, default=str))
    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
