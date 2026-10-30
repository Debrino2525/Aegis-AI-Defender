#!/usr/bin/env python3
"""Part 2I + 4.4: wall-clock per pipeline step; port sets vs localhost."""
import asyncio
import json
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "11_scan_perf.json"

from aegis.core.config import ScanConfig, TOP_PORTS
from aegis.discovery.port_scanner import AsyncPortScanner
from aegis.discovery.fingerprint import ServiceFingerprinter
from aegis.discovery.cpe_matcher import CPEMatcher
from aegis.checks.http_checks import HTTPMisconfigChecker
from aegis.checks.tls_auditor import TLSAuditor
from aegis.checks.template_engine import TemplateEngine
from aegis.checks.smb_checks import SMBAuditor
from aegis.checks.dns_checks import DNSAuditor


async def timed(name, coro):
    t0 = time.perf_counter()
    try:
        result = await coro
        err = None
    except Exception as e:
        result = None
        err = repr(e)
    return name, time.perf_counter() - t0, result, err


async def pipeline(host: str, ports: list, label: str):
    cfg = ScanConfig(target=host, ports=ports, concurrency=200, connect_timeout=1.5, read_timeout=2.0)
    out = {"label": label, "host": host, "n_ports": len(ports)}
    t_all = time.perf_counter()

    t0 = time.perf_counter()
    try:
        ip = socket.gethostbyname(host)
        resolve_err = None
    except Exception as e:
        ip = host
        resolve_err = repr(e)
    out["resolve_s"] = time.perf_counter() - t0
    out["ip"] = ip
    out["resolve_err"] = resolve_err

    scanner = AsyncPortScanner(cfg)
    name, dt, open_ports, err = await timed("port_discovery", scanner.scan_target(ip, ports))
    out["port_discovery_s"] = dt
    out["open_ports"] = open_ports
    out["port_err"] = err
    if not open_ports:
        out["total_s"] = time.perf_counter() - t_all
        out["fingerprint_s"] = None
        out["http_s"] = None
        out["tls_s"] = None
        out["smb_s"] = None
        out["dns_s"] = None
        out["templates_s"] = None
        return out

    fp = ServiceFingerprinter(cfg)
    t0 = time.perf_counter()
    services_raw = await asyncio.gather(*[fp.fingerprint(ip, p) for p in open_ports], return_exceptions=True)
    out["fingerprint_s"] = time.perf_counter() - t0
    services = [s for s in services_raw if not isinstance(s, Exception)]
    out["services"] = [
        {"port": s.port, "service_name": s.service_name, "product": s.product, "version": s.version, "tls": s.tls}
        for s in services
    ]

    http_svcs = [s for s in services if s.service_name in ("http", "https")]
    t0 = time.perf_counter()
    http_n = 0
    for svc in http_svcs:
        checker = HTTPMisconfigChecker(cfg)
        hf = await checker.check(host, svc.port, svc.tls)
        http_n += len(hf)
    out["http_s"] = time.perf_counter() - t0
    out["http_findings"] = http_n
    out["http_targets"] = len(http_svcs)

    tls_svcs = [s for s in services if s.tls or s.port in (443, 8443)]
    t0 = time.perf_counter()
    tls_n = 0
    for svc in tls_svcs:
        tls = TLSAuditor(cfg)
        tf = await tls.audit(ip, svc.port)
        tls_n += len(tf)
    out["tls_s"] = time.perf_counter() - t0
    out["tls_findings"] = tls_n
    out["tls_targets"] = len(tls_svcs)

    t0 = time.perf_counter()
    te = TemplateEngine(cfg)
    tf2 = await te.run_all(ip, open_ports) if te.templates else []
    out["templates_s"] = time.perf_counter() - t0
    out["template_findings"] = len(tf2)
    out["n_templates"] = len(te.templates)

    smb_svcs = [s for s in services if s.service_name in ("smb", "microsoft-ds", "netbios-ssn") or s.port in (139, 445)]
    t0 = time.perf_counter()
    smb_n = 0
    for svc in smb_svcs:
        smb = SMBAuditor(cfg)
        sf = await smb.audit(host, svc.port)
        smb_n += len(sf)
    out["smb_s"] = time.perf_counter() - t0
    out["smb_findings"] = smb_n

    dns_svcs = [s for s in services if s.service_name == "dns" or s.port == 53]
    t0 = time.perf_counter()
    dns_n = 0
    for svc in dns_svcs:
        dns = DNSAuditor(cfg)
        df = await dns.audit(host, svc.port)
        dns_n += len(df)
    out["dns_s"] = time.perf_counter() - t0
    out["dns_findings"] = dns_n

    out["total_s"] = time.perf_counter() - t_all
    out["sequential_note"] = "HTTP then TLS then templates then SMB then DNS; each service awaited in a for-loop"
    return out


async def main():
    # Listeners on localhost so some ports are open
    servers = []
    async def _discard(r, w):
        try:
            w.close()
            await w.wait_closed()
        except Exception:
            pass
    for p in (18080, 18022):
        try:
            servers.append(await asyncio.start_server(_discard, "127.0.0.1", p))
        except OSError:
            pass

    jobs = []
    jobs.append(await pipeline("127.0.0.1", list(TOP_PORTS), "localhost_default_33"))
    jobs.append(await pipeline("127.0.0.1", list(range(1, 1025)), "localhost_1_1024"))
    # 1-65535 is huge; still run as specified against localhost
    jobs.append(await pipeline("127.0.0.1", list(range(1, 65536)), "localhost_1_65535"))

    for s in servers:
        s.close()
        await s.wait_closed()

    payload = {
        "top_ports_count": len(TOP_PORTS),
        "top_ports": TOP_PORTS,
        "runs": jobs,
        "remote_lab_host": None,
        "remote_status": "COULD-NOT-VERIFY: no remote lab host under our control; skipped per spec (do not scan unknown internet)",
    }
    OUT.write_text(json.dumps(payload, indent=2, default=str))
    print(json.dumps({
        "top_ports_count": len(TOP_PORTS),
        "runs": [
            {k: r[k] for k in r if k != "services"}
            for r in jobs
        ],
        "remote_status": payload["remote_status"],
    }, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
