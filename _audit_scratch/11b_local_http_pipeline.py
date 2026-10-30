#!/usr/bin/env python3
"""Part 2I: sequential pipeline wall-clock against a local HTTP listener we control."""
import asyncio, json, time, sys
from pathlib import Path
sys.path.insert(0, "/workspace")
from aegis.core.config import ScanConfig
from aegis.discovery.port_scanner import AsyncPortScanner
from aegis.discovery.fingerprint import ServiceFingerprinter
from aegis.checks.http_checks import HTTPMisconfigChecker
from aegis.checks.tls_auditor import TLSAuditor
from aegis.checks.template_engine import TemplateEngine
from aegis.checks.smb_checks import SMBAuditor
from aegis.checks.dns_checks import DNSAuditor

async def handle(reader, writer):
    try:
        await asyncio.wait_for(reader.read(1024), timeout=1.0)
    except Exception:
        pass
    body = b"<html><title>aegis-audit</title></html>"
    resp = (
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
    )
    try:
        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

async def timed(label, coro):
    t0 = time.perf_counter()
    try:
        res = await coro
        err = None
    except Exception as e:
        res, err = None, repr(e)
    return label, time.perf_counter() - t0, res, err

async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", 18080)
    host, ports = "127.0.0.1", [22, 80, 443, 18080, 8080, 8443]
    cfg = ScanConfig(target=host, ports=ports, concurrency=50, connect_timeout=1.5, read_timeout=2.0)
    out = {}
    t_all = time.perf_counter()
    scanner = AsyncPortScanner(cfg)
    _, out["port_discovery_s"], open_ports, out["port_err"] = await timed("p", scanner.scan_target(host, ports))
    out["open_ports"] = open_ports
    fp = ServiceFingerprinter(cfg)
    t0 = time.perf_counter()
    services = []
    # sequential fingerprint like a naive loop AND gather
    t_seq = 0.0
    seq_svcs = []
    for p in open_ports:
        t1 = time.perf_counter()
        seq_svcs.append(await fp.fingerprint(host, p))
        t_seq += time.perf_counter() - t1
    out["fingerprint_sequential_s"] = t_seq
    t0 = time.perf_counter()
    gathered = await asyncio.gather(*[fp.fingerprint(host, p) for p in open_ports], return_exceptions=True)
    out["fingerprint_gather_s"] = time.perf_counter() - t0
    services = [s for s in seq_svcs]
    out["services"] = [{"port": s.port, "service_name": s.service_name, "product": s.product, "version": s.version, "tls": s.tls} for s in services]

    http_svcs = [s for s in services if s.service_name in ("http", "https") or s.port in (80, 8080, 18080)]
    t0 = time.perf_counter()
    n = 0
    for svc in http_svcs:
        n += len(await HTTPMisconfigChecker(cfg).check(host, svc.port, svc.tls))
    out["http_s"] = time.perf_counter() - t0
    out["http_findings"] = n
    out["http_targets"] = [{"port": s.port, "name": s.service_name} for s in http_svcs]

    tls_svcs = [s for s in services if s.tls or s.port in (443, 8443)]
    t0 = time.perf_counter()
    n = 0
    for svc in tls_svcs:
        n += len(await TLSAuditor(cfg).audit(host, svc.port))
    out["tls_s"] = time.perf_counter() - t0
    out["tls_findings"] = n
    out["tls_targets"] = len(tls_svcs)

    te = TemplateEngine(cfg)
    t0 = time.perf_counter()
    tf = await te.run_all(host, open_ports)
    out["templates_s"] = time.perf_counter() - t0
    out["template_findings"] = len(tf)

    t0 = time.perf_counter()
    smb_n = 0
    for s in services:
        if s.port in (139, 445):
            smb_n += len(await SMBAuditor(cfg).audit(host, s.port))
    out["smb_s"] = time.perf_counter() - t0

    t0 = time.perf_counter()
    dns_n = 0
    for s in services:
        if s.port == 53:
            dns_n += len(await DNSAuditor(cfg).audit(host, s.port))
    out["dns_s"] = time.perf_counter() - t0
    out["total_s"] = time.perf_counter() - t_all
    srv.close()
    await srv.wait_closed()
    Path("/workspace/_audit_scratch/results/11b_local_http.json").write_text(json.dumps(out, indent=2, default=str))
    print(json.dumps(out, indent=2, default=str))

if __name__ == "__main__":
    asyncio.run(main())
