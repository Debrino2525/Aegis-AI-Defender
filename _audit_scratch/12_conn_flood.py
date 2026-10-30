#!/usr/bin/env python3
"""Part 4.5: 2000+ concurrent connections; sample-loop duration and WS responsiveness."""
import asyncio
import json
import os
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "12_conn_flood.json"

import psutil
import httpx
from aegis.monitor.network_monitor import NetworkMonitor

N_CONNS = int(os.environ.get("AEGIS_AUDIT_N_CONNS", "2000"))
WS_URL = os.environ.get("AEGIS_AUDIT_WS", "ws://127.0.0.1:8765/ws/monitor")
HTTP_URL = os.environ.get("AEGIS_AUDIT_BASE", "http://127.0.0.1:8765")


def log(msg):
    print(msg, flush=True)
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def pick_ip():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return addr.address
    return "127.0.0.1"


async def _keep(reader, writer):
    try:
        await asyncio.sleep(120)
    except Exception:
        pass
    try:
        writer.close()
    except Exception:
        pass


async def run_flood(bind_ip: str, port: int, n: int):
    server = await asyncio.start_server(_keep, bind_ip, port, backlog=min(n + 50, 4096))
    clients = []
    errors = 0
    t0 = time.perf_counter()
    batch = 100
    for i in range(0, n, batch):
        tasks = []
        for _ in range(min(batch, n - i)):
            tasks.append(asyncio.open_connection(bind_ip, port))
        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=15)
        except asyncio.TimeoutError:
            errors += len(tasks)
            log(f"batch timeout at {i}")
            break
        for r in results:
            if isinstance(r, Exception):
                errors += 1
            else:
                clients.append(r)
        log(f"opened {len(clients)} errors {errors}")
    open_s = time.perf_counter() - t0
    return server, clients, errors, open_s


def time_net_connections():
    t0 = time.perf_counter()
    raw = psutil.net_connections(kind="inet")
    return time.perf_counter() - t0, len(raw)


async def time_one_sample(timeout=45.0):
    mon = NetworkMonitor()
    t0 = time.perf_counter()
    try:
        await asyncio.wait_for(mon._sample_connections(), timeout=timeout)
        dt = time.perf_counter() - t0
        return {
            "sample_s": dt,
            "timed_out": False,
            "kept_connections": len(mon.current_connections),
            "n_alerts": len(mon.alerts),
            "alert_ids": [a.get("pattern_id") for a in mon.alerts],
            "len_conn_history": len(mon.conn_history),
        }
    except asyncio.TimeoutError:
        return {
            "sample_s": time.perf_counter() - t0,
            "timed_out": True,
            "kept_connections": len(mon.current_connections),
            "n_alerts": len(mon.alerts),
        }


async def ws_probe():
    result = {"ws": None, "http_monitor": None}
    try:
        import websockets
        t0 = time.perf_counter()
        async with websockets.connect(WS_URL, open_timeout=4, close_timeout=2) as ws:
            msg = await asyncio.wait_for(ws.recv(), timeout=6)
            dt = time.perf_counter() - t0
            result["ws"] = {
                "elapsed_s": dt,
                "bytes": len(msg) if isinstance(msg, (str, bytes)) else None,
                "ok": True,
            }
    except Exception as e:
        result["ws"] = {"ok": False, "error": repr(e), "elapsed_s": None}
    try:
        t0 = time.perf_counter()
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(f"{HTTP_URL}/api/monitor")
            result["http_monitor"] = {
                "elapsed_s": time.perf_counter() - t0,
                "status": r.status_code,
                "bytes": len(r.content),
            }
    except Exception as e:
        result["http_monitor"] = {"ok": False, "error": repr(e)}
    return result


async def main():
    bind_ip = pick_ip()
    port = 18443
    log(f"bind {bind_ip}:{port}")
    log("baseline net_connections")
    b_nc_s, b_nc_n = time_net_connections()
    log(f"baseline nc {b_nc_n} in {b_nc_s}s")
    log("baseline sample")
    baseline_sample = await time_one_sample(timeout=20)
    log(f"baseline sample {baseline_sample}")
    log("ws_before")
    ws_before = await ws_probe()
    log(f"ws_before {ws_before}")

    server, clients, errors, open_s = await run_flood(bind_ip, port, N_CONNS)
    log(f"flood opened {len(clients)} in {open_s}s errors {errors}")
    await asyncio.sleep(0.3)
    load_nc_s, load_nc_n = time_net_connections()
    log(f"loaded nc {load_nc_n} in {load_nc_s}s")
    loaded_sample = await time_one_sample(timeout=45)
    log(f"loaded sample {loaded_sample}")
    ws_after = await ws_probe()
    log(f"ws_after {ws_after}")

    payload = {
        "bind_ip": bind_ip,
        "port": port,
        "requested": N_CONNS,
        "opened": len(clients),
        "open_errors": errors,
        "open_s": open_s,
        "baseline_net_connections_s": b_nc_s,
        "baseline_net_connections_n": b_nc_n,
        "loaded_net_connections_s": load_nc_s,
        "loaded_net_connections_n": load_nc_n,
        "baseline_sample": baseline_sample,
        "loaded_sample": loaded_sample,
        "ws_before": ws_before,
        "ws_after": ws_after,
    }

    for r, w in clients:
        try:
            w.close()
        except Exception:
            pass
    server.close()
    try:
        await asyncio.wait_for(server.wait_closed(), timeout=5)
    except Exception:
        pass

    OUT.write_text(json.dumps(payload, indent=2, default=str))
    print(json.dumps(payload, indent=2, default=str), flush=True)


if __name__ == "__main__":
    asyncio.run(main())
