#!/usr/bin/env python3
"""UDP probe under PYTHONASYNCIODEBUG to see the non-blocking ValueError."""
import asyncio, json, socket, traceback, sys
from pathlib import Path
sys.path.insert(0, "/workspace")
from aegis.core.config import ScanConfig
from aegis.discovery.port_scanner import AsyncPortScanner

async def main():
    loop = asyncio.get_event_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    info = {
        "gettimeout": sock.gettimeout(),
        "debug": loop.get_debug(),
    }
    try:
        await loop.sock_sendto(sock, b"\x00", ("127.0.0.1", 18053))
        info["send"] = "ok"
    except Exception:
        info["send"] = traceback.format_exc()
    sock.close()

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock2.setblocking(False)
    try:
        await loop.sock_sendto(sock2, b"hello-echo", ("127.0.0.1", 9))  # discard
        info["nonblocking_send_to_discard"] = "ok"
    except Exception:
        info["nonblocking_send_to_discard"] = traceback.format_exc()
    sock2.close()
    Path("/workspace/_audit_scratch/results/05b_udp_debug.json").write_text(json.dumps(info, indent=2))
    print(json.dumps(info, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
