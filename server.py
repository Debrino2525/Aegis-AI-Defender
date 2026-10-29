"""
Aegis Web API — FastAPI backend with WebSocket real-time scan streaming.
"""

import asyncio
import json
import uuid
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Force UTF-8
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add parent dir to path for aegis imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from aegis.core.config import ScanConfig, TOP_PORTS
from aegis.core.engine import ScanEngine
from aegis.database.db import VulnerabilityDatabase
from aegis.database.sync import ThreatFeedSync
from aegis.intel.attack_mapper import build_attack_summary
from aegis.intel.asset_intelligence import (
    compute_aegis_risk_score, compute_risk_label,
    compute_business_risk, build_contributing_factors,
    generate_top_insights, categorize_services, CATEGORY_ICONS
)
from aegis.reporting.html_reporter import HTMLReporter
from aegis.reporting.csv_reporter import CSVReporter
from aegis.reporting.sarif_reporter import SARIFReporter
from aegis.monitor.network_monitor import NetworkMonitor
from aegis.monitor.ai_analyst import AIAnalyst
from aegis.monitor.remediation import remediator
from datetime import timezone
from aegis.core.verifier import FindingVerifier

app = FastAPI(title="Aegis Vulnerability Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:[0-9]+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Mount static files directory
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

# In-memory scan store (use a real DB in production)
scans: Dict[str, Dict[str, Any]] = {}

# ── Monitor singleton ────────────────────────────────────────────────────────
monitor = NetworkMonitor()
analyst = AIAnalyst()
verifier = FindingVerifier()


from aegis.alerting.router import alert_router
from aegis.alerting.security import verify_triage_token

@app.on_event("startup")
async def _startup():
    """Auto-start the network monitor and alert router when the server boots."""
    await monitor.start()
    await alert_router.start()


@app.on_event("shutdown")
async def _shutdown():
    monitor.stop()
    alert_router.stop()


import re
from aegis.core.target import normalize_target

class ScanRequest(BaseModel):
    target: str
    ports: Optional[str] = None   # comma-separated, e.g. "80,443,22"
    concurrency: int = 200

    def normalize(self) -> Tuple[str, Optional[int]]:
        clean_host, port = normalize_target(self.target)
        if clean_host:
            self.target = clean_host
        return clean_host, port

    def validate_security(self):
        t = self.target.strip()
        if not t:
            raise HTTPException(status_code=400, detail="Target cannot be empty.")
        clean_host, _ = self.normalize()
        if not clean_host:
            raise HTTPException(status_code=400, detail="Could not extract a valid host or IP from the provided target.")
        # Reject shell metacharacters and control characters on normalized target
        if not re.match(r'^[a-zA-Z0-9\.\-_:]+$', clean_host):
            raise HTTPException(status_code=400, detail="Invalid target format: disallowed characters detected in host.")
        if self.concurrency < 1 or self.concurrency > 1000:
            raise HTTPException(status_code=400, detail="Concurrency must be between 1 and 1000.")


# ── Serve the single-page frontend ─────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = Path(__file__).parent / "static" / "index.html"
    return html_path.read_text(encoding="utf-8")


# ── REST: list all scans ────────────────────────────────────────────────────
@app.get("/api/scans")
async def list_scans():
    result = []
    for sid, scan in scans.items():
        result.append({
            "id": sid,
            "target": scan["target"],
            "status": scan["status"],
            "started_at": scan.get("started_at"),
            "duration": scan.get("duration"),
            "total_findings": scan.get("total_findings", 0),
            "severity_breakdown": scan.get("severity_breakdown", {}),
        })
    return sorted(result, key=lambda x: x.get("started_at") or "", reverse=True)


# ── REST: get single scan report ────────────────────────────────────────────
@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


# ── REST: download scan report in various formats ───────────────────────────
@app.get("/api/scans/{scan_id}/download/{format}")
async def download_report(scan_id: str, format: str):
    """Download scan report in specified format (html, csv, sarif, json)."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans[scan_id]

    # Convert scan dict to ScanReport model
    from aegis.core.models import ScanReport, HostScanResult, Finding, Severity
    from datetime import datetime

    findings = []
    for f in scan.get("findings", []):
        findings.append(Finding(
            id=f["id"],
            title=f["title"],
            target=f["target"],
            port=f.get("port"),
            service=f.get("service"),
            severity=Severity(f["severity"]),
            cvss_score=f.get("cvss_score", 0.0),
            epss_score=f.get("epss_score", 0.0),
            is_cisa_kev=f.get("is_cisa_kev", False),
            composite_risk_score=f.get("composite_risk_score", 0.0),
            confidence=f.get("confidence", "MEDIUM"),
            description=f["description"],
            evidence=f["evidence"],
            remediation=f.get("remediation"),
            cve_id=f.get("cve_id"),
            references=f.get("references", []),
            timestamp=datetime.fromisoformat(f.get("timestamp", datetime.utcnow().isoformat()))
        ))

    services = []
    for s in scan.get("services", []):
        services.append({
            "port": s["port"],
            "protocol": s.get("protocol", "tcp"),
            "service_name": s.get("service_name", "unknown"),
            "product": s.get("product"),
            "version": s.get("version"),
            "banner": s.get("banner"),
            "tls": s.get("tls", False)
        })

    host_result = HostScanResult(
        host=scan["target"],
        ip=scan.get("ip", scan["target"]),
        open_ports=scan.get("open_ports", []),
        services=services,
        findings=findings
    )

    report = ScanReport(
        scan_id=scan_id,
        target=scan["target"],
        started_at=datetime.fromisoformat(scan["started_at"]),
        completed_at=datetime.fromisoformat(scan.get("completed_at", datetime.utcnow().isoformat())),
        duration_seconds=scan.get("duration", 0.0),
        hosts=[host_result],
        total_findings=scan.get("total_findings", 0),
        severity_breakdown=scan.get("severity_breakdown", {})
    )

    # Generate report in requested format
    if format == "html":
        html_content = HTMLReporter.generate(report)
        return HTMLResponse(content=html_content, media_type="text/html")
    elif format == "csv":
        csv_content = CSVReporter.generate(report)
        return Response(content=csv_content, media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=aegis_scan_{scan_id}.csv"})
    elif format == "sarif":
        sarif_content = SARIFReporter.generate(report)
        return JSONResponse(content=sarif_content,
                          headers={"Content-Disposition": f"attachment; filename=aegis_scan_{scan_id}.sarif.json"})
    elif format == "json":
        json_content = report.model_dump(mode="json")
        return JSONResponse(content=json_content,
                          headers={"Content-Disposition": f"attachment; filename=aegis_scan_{scan_id}.json"})
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


# ── REST: delete scan ───────────────────────────────────────────────────────
@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scans[scan_id]
    return {"ok": True}


# ── REST: reset platform to pristine clean state ────────────────────────────
@app.post("/api/reset")
async def reset_platform():
    """Resets all scan data, findings, monitor alerts, and watchlist to clean state."""
    scans.clear()
    monitor.alerts.clear()
    monitor.seen_alert_keys.clear()
    monitor.watched_targets.clear()
    monitor.conn_history.clear()
    monitor.scan_tracker.clear()
    monitor.stats["alerts_generated"] = 0
    analyst.clear()
    return {"ok": True, "message": "Platform reset to clean state"}


# ── REST: Finding Verification & Manual Reproduction (PoC) ──────────────────
class VerifyFindingRequest(BaseModel):
    finding_id: str
    title: str
    target: str
    port: Optional[int] = None


@app.get("/api/findings/instructions")
async def get_finding_instructions(finding_id: str, title: str, target: str, port: Optional[int] = None):
    """Returns manual reproduction instructions, cURL, PowerShell & PoC steps."""
    return verifier.get_instructions(finding_id, title, target, port)


@app.post("/api/findings/verify")
async def verify_finding_live(req: VerifyFindingRequest):
    """Executes a real-time targeted automated re-test against the finding and returns proof."""
    return await verifier.verify_finding(req.finding_id, req.title, req.target, req.port)


# ── REST: aggregated platform intelligence ───────────────────────────────────
@app.get("/api/intelligence")
async def get_intelligence():
    """Returns aggregated risk intelligence across all completed scans."""
    all_findings = []
    all_services = []
    all_hosts = []

    for sid, scan in scans.items():
        if scan["status"] == "done":
            all_findings.extend(scan.get("findings", []))
            all_services.extend(scan.get("services", []))
            all_hosts.append({
                "host": scan["target"],
                "scan_id": sid,
                "open_ports": scan.get("open_ports", []),
                "total_findings": scan.get("total_findings", 0),
                "severity_breakdown": scan.get("severity_breakdown", {}),
                "duration": scan.get("duration"),
                "started_at": scan.get("started_at"),
            })

    risk_score = compute_aegis_risk_score(all_findings)
    business_risk = compute_business_risk(all_findings)
    contributing = build_contributing_factors(all_findings)
    attack_summary = build_attack_summary(all_findings)
    top_insights = generate_top_insights(all_findings)
    tech_categories = categorize_services(all_services)

    sev_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev_totals[f.get("severity", "INFO")] = sev_totals.get(f.get("severity", "INFO"), 0) + 1

    return {
        "risk_score": risk_score,
        "risk_label": compute_risk_label(risk_score),
        "total_assets": len(all_hosts),
        "total_findings": len(all_findings),
        "severity_totals": sev_totals,
        "business_risk": business_risk,
        "contributing_factors": contributing,
        "attack_summary": attack_summary,
        "top_insights": top_insights,
        "tech_categories": {
            cat: {
                "count": len(svcs),
                "icon": CATEGORY_ICONS.get(cat, "⚙"),
                "services": svcs[:5],
            }
            for cat, svcs in tech_categories.items()
        },
        "hosts": all_hosts,
    }


# ── REST: start a scan (returns scan_id immediately) ───────────────────────
@app.post("/api/scans")
async def start_scan(req: ScanRequest):
    req.validate_security()
    clean_host, custom_port = req.normalize()
    scan_id = str(uuid.uuid4())[:8].upper()
    ports = TOP_PORTS
    if req.ports:
        try:
            ports = [int(p.strip()) for p in req.ports.split(",") if p.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid ports format")
    elif custom_port and custom_port not in ports:
        ports = [custom_port] + [p for p in ports if p != custom_port]

    scans[scan_id] = {
        "id": scan_id,
        "target": clean_host,
        "status": "queued",
        "started_at": datetime.utcnow().isoformat(),
        "progress": 0,
        "log": [],
        "total_findings": 0,
        "severity_breakdown": {},
        "findings": [],
        "services": [],
        "open_ports": [],
    }

    # Run scan in background
    asyncio.create_task(_run_scan(scan_id, clean_host, ports, req.concurrency))
    return {"scan_id": scan_id}


# ── REST: Threat Intelligence Feeds & Connectors ───────────────────────────
@app.get("/api/threat/feeds")
async def get_threat_feeds():
    """Returns the live configuration, connectivity and record counts of all threat intel feeds."""
    db = VulnerabilityDatabase()
    syncer = ThreatFeedSync(db)
    return syncer.get_feeds_status()


@app.post("/api/threat/feeds/sync")
async def sync_threat_feeds():
    """Triggers synchronization across all connected threat intelligence feeds."""
    asyncio.create_task(_run_update())
    return {"ok": True, "message": "Multi-source threat feed synchronization started in background"}


@app.post("/api/update")
async def trigger_update():
    asyncio.create_task(_run_update())
    return {"ok": True, "message": "Feed sync started in background"}


# ── REST: Monitor state snapshot ────────────────────────────────────────────
@app.get("/api/monitor")
async def get_monitor():
    """Returns the current live monitor state (connections, graph, alerts, baselines)."""
    state = monitor.get_state()
    state["incidents"] = analyst.analyze(monitor.alerts)
    return state


@app.post("/api/monitor/start")
async def start_monitor():
    if not monitor.running:
        await monitor.start()
    return {"ok": True, "running": monitor.running}


@app.post("/api/monitor/stop")
async def stop_monitor():
    monitor.stop()
    return {"ok": True, "running": monitor.running}


@app.post("/api/monitor/alerts/{alert_id}/ack")
async def ack_alert(alert_id: str):
    ok = monitor.acknowledge_alert(alert_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"ok": True}


class AddTargetRequest(BaseModel):
    target: str


@app.get("/api/monitor/targets")
async def list_monitored_targets():
    return list(monitor.watched_targets.values())


@app.post("/api/monitor/targets")
async def add_monitored_target(req: AddTargetRequest):
    try:
        target_obj = monitor.add_target(req.target)
        # Trigger an immediate background probe so results appear fast
        asyncio.create_task(monitor._probe_single_target(target_obj))
        return target_obj
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/monitor/targets/{target_id}")
async def remove_monitored_target(target_id: str):
    ok = monitor.remove_target(target_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"ok": True}


# ── REST: Critical Alert Routing & Zero Trust Escalation ─────────────────
@app.get("/api/alerting/status")
async def get_alerting_status():
    """Returns live status of critical alert routing channels, queue depths, and canary."""
    return alert_router.get_status()


@app.get("/api/alerting/alerts")
async def list_critical_alerts():
    """Lists recent critical alerts with DoD Zero Trust tags, acknowledgment state, and escalation level."""
    return alert_router.queue.list_recent_alerts(limit=50)


@app.post("/api/alerting/alerts/{alert_id}/ack")
async def ack_critical_alert(alert_id: str, responder: str = "SOC-Analyst"):
    """Acknowledges a critical alert, halting all active escalation timers."""
    ok = alert_router.acknowledge_alert(alert_id, responder)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found or already acknowledged")
    return {"ok": True, "message": f"Alert {alert_id} acknowledged by {responder}"}


@app.get("/api/alerting/triage/{token}")
async def verify_triage(token: str):
    """Verifies a zero-trust one-time cryptographic triage token from an SMS/Chat link."""
    is_valid, payload, reason = verify_triage_token(token)
    if not is_valid:
        raise HTTPException(status_code=403, detail=f"Invalid or expired token: {reason}")
    alert = alert_router.queue.get_alert(payload["aid"])
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"valid": True, "payload": payload, "alert": alert}


class TestAlertRequest(BaseModel):
    title: str = "Simulated Ransomware Lateral Movement (Test)"
    target: str = "10.0.0.1"


@app.post("/api/alerting/test")
async def trigger_test_critical_alert(req: TestAlertRequest):
    """Triggers an end-to-end critical alert routing simulation to test channels and adapters."""
    test_alert = {
        "pattern_id": "AEGIS-BEH-010",
        "title": req.title,
        "severity": "CRITICAL",
        "source_ip": req.target,
        "dest_ip": "10.0.0.254",
        "dest_port": 445,
        "process": "test_simulator.exe",
        "tactic": "Lateral Movement",
        "evidence": "Simulated multi-host SMB propagation test"
    }
    routed = await alert_router.route_behavioral_alert(test_alert)
    return {
        "ok": True,
        "alert_id": routed.alert_id if routed else None,
        "status": "Routed through critical delivery channels"
    }


# ── WebSocket: real-time monitor stream ─────────────────────────────────────

# ── REST: Platform Settings, Integrations & On-Call Directory ─────────────
def _mask_key(val: str) -> str:
    if not val:
        return ""
    v = val.strip()
    if len(v) <= 8:
        return "***"
    return v[:4] + "..." + v[-4:]

def _update_env_file(updates: Dict[str, str], env_path: Path = Path(".env")):
    existing_lines = []
    if env_path.exists():
        existing_lines = env_path.read_text(encoding="utf-8").splitlines()
    seen_keys = set()
    new_lines = []
    for line in existing_lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k in updates:
                new_lines.append(f"{k}={updates[k]}")
                seen_keys.add(k)
                continue
        new_lines.append(line)
    for k, v in updates.items():
        if k not in seen_keys:
            new_lines.append(f"{k}={v}")
    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

@app.get("/api/settings")
async def get_platform_settings():
    """Returns live system configuration with masked credentials for UI settings form."""
    return {
        "threat_intel": {
            "nvd_api_key": os.getenv("NVD_API_KEY", ""),
            "abuseipdb_api_key": os.getenv("ABUSEIPDB_API_KEY", ""),
            "otx_api_key": os.getenv("OTX_API_KEY", ""),
            "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY", ""),
            "has_nvd": bool(os.getenv("NVD_API_KEY")),
            "has_abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY")),
            "has_otx": bool(os.getenv("OTX_API_KEY")),
            "has_virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
        },
        "alerting": {
            "arkesel_api_key": os.getenv("ARKESEL_API_KEY", ""),
            "arkesel_sender_id": os.getenv("ARKESEL_SENDER_ID", "AegisAI"),
            "hubtel_client_id": os.getenv("HUBTEL_CLIENT_ID", ""),
            "hubtel_client_secret": os.getenv("HUBTEL_CLIENT_SECRET", ""),
            "hubtel_sender_id": os.getenv("HUBTEL_SENDER_ID", "AegisAI"),
            "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
            "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
            "whatsapp_api_token": os.getenv("WHATSAPP_API_TOKEN", ""),
            "whatsapp_phone_number_id": os.getenv("WHATSAPP_PHONE_NUMBER_ID", ""),
            "critical_alert_webhook_url": os.getenv("CRITICAL_ALERT_WEBHOOK_URL", ""),
            "modem_serial_port": os.getenv("MODEM_SERIAL_PORT", "COM3"),
            "modem_baudrate": int(os.getenv("MODEM_BAUDRATE", "115200")),
            "canary_heartbeat_url": os.getenv("CANARY_HEARTBEAT_URL", ""),
            "aegis_console_url": os.getenv("AEGIS_CONSOLE_URL", "http://localhost:8000")
        }
    }

class SettingsPayload(BaseModel):
    threat_intel: Optional[Dict[str, Any]] = None
    alerting: Optional[Dict[str, Any]] = None

@app.post("/api/settings")
async def save_platform_settings(payload: SettingsPayload):
    """Persists updated settings into .env and hot-reloads runtime services."""
    updates = {}
    if payload.threat_intel:
        ti = payload.threat_intel
        if "nvd_api_key" in ti: updates["NVD_API_KEY"] = str(ti["nvd_api_key"]).strip()
        if "abuseipdb_api_key" in ti: updates["ABUSEIPDB_API_KEY"] = str(ti["abuseipdb_api_key"]).strip()
        if "otx_api_key" in ti: updates["OTX_API_KEY"] = str(ti["otx_api_key"]).strip()
        if "virustotal_api_key" in ti: updates["VIRUSTOTAL_API_KEY"] = str(ti["virustotal_api_key"]).strip()
    if payload.alerting:
        al = payload.alerting
        if "arkesel_api_key" in al: updates["ARKESEL_API_KEY"] = str(al["arkesel_api_key"]).strip()
        if "arkesel_sender_id" in al: updates["ARKESEL_SENDER_ID"] = str(al["arkesel_sender_id"]).strip()
        if "hubtel_client_id" in al: updates["HUBTEL_CLIENT_ID"] = str(al["hubtel_client_id"]).strip()
        if "hubtel_client_secret" in al: updates["HUBTEL_CLIENT_SECRET"] = str(al["hubtel_client_secret"]).strip()
        if "hubtel_sender_id" in al: updates["HUBTEL_SENDER_ID"] = str(al["hubtel_sender_id"]).strip()
        if "telegram_bot_token" in al: updates["TELEGRAM_BOT_TOKEN"] = str(al["telegram_bot_token"]).strip()
        if "telegram_chat_id" in al: updates["TELEGRAM_CHAT_ID"] = str(al["telegram_chat_id"]).strip()
        if "whatsapp_api_token" in al: updates["WHATSAPP_API_TOKEN"] = str(al["whatsapp_api_token"]).strip()
        if "whatsapp_phone_number_id" in al: updates["WHATSAPP_PHONE_NUMBER_ID"] = str(al["whatsapp_phone_number_id"]).strip()
        if "critical_alert_webhook_url" in al: updates["CRITICAL_ALERT_WEBHOOK_URL"] = str(al["critical_alert_webhook_url"]).strip()
        if "modem_serial_port" in al: updates["MODEM_SERIAL_PORT"] = str(al["modem_serial_port"]).strip()
        if "modem_baudrate" in al: updates["MODEM_BAUDRATE"] = str(al["modem_baudrate"]).strip()
        if "canary_heartbeat_url" in al: updates["CANARY_HEARTBEAT_URL"] = str(al["canary_heartbeat_url"]).strip()
        if "aegis_console_url" in al: updates["AEGIS_CONSOLE_URL"] = str(al["aegis_console_url"]).strip()

    # Apply to os.environ and write to .env
    for k, v in updates.items():
        os.environ[k] = v
    _update_env_file(updates)

    # Hot reload alert router adapters
    alert_router.adapter_sms.arkesel_api_key = os.getenv("ARKESEL_API_KEY", "").strip()
    alert_router.adapter_sms.arkesel_sender = os.getenv("ARKESEL_SENDER_ID", "AegisAI").strip()[:11]
    alert_router.adapter_sms.hubtel_client_id = os.getenv("HUBTEL_CLIENT_ID", "").strip()
    alert_router.adapter_sms.hubtel_client_secret = os.getenv("HUBTEL_CLIENT_SECRET", "").strip()
    alert_router.adapter_sms.hubtel_sender = os.getenv("HUBTEL_SENDER_ID", "AegisAI").strip()[:11]
    alert_router.adapter_webhook.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    alert_router.adapter_webhook.telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    alert_router.adapter_webhook.whatsapp_token = os.getenv("WHATSAPP_API_TOKEN", "").strip()
    alert_router.adapter_webhook.whatsapp_phone_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID", "").strip()
    alert_router.adapter_webhook.generic_webhook_url = os.getenv("CRITICAL_ALERT_WEBHOOK_URL", "").strip()
    alert_router.adapter_modem.port = os.getenv("MODEM_SERIAL_PORT", "COM3").strip()
    alert_router.heartbeat.canary_url = os.getenv("CANARY_HEARTBEAT_URL", "").strip()
    alert_router.base_console_url = os.getenv("AEGIS_CONSOLE_URL", "http://localhost:8000").rstrip("/")
    return {"ok": True, "message": "Settings successfully saved and reloaded!"}

# ── On-Call Responders & Ownership REST Endpoints ─────────────────────────
@app.get("/api/alerting/contacts")
async def list_oncall_contacts():
    return alert_router.queue.list_contacts()

class ContactPayload(BaseModel):
    contact_id: Optional[str] = None
    name: str
    role: str = "SOC Responder"
    phone: str
    email: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    whatsapp_number: Optional[str] = None
    is_active: bool = True

@app.post("/api/alerting/contacts")
async def save_oncall_contact(c: ContactPayload):
    cid = c.contact_id or f"ONCALL-{uuid.uuid4().hex[:6].upper()}"
    contact_dict = {
        "contact_id": cid,
        "name": c.name.strip(),
        "role": c.role.strip(),
        "phone": c.phone.strip(),
        "email": (c.email or "").strip(),
        "telegram_chat_id": (c.telegram_chat_id or "").strip(),
        "whatsapp_number": (c.whatsapp_number or c.phone).strip(),
        "is_active": c.is_active
    }
    from aegis.alerting.models import OnCallContact
    contact_obj = OnCallContact(**contact_dict)
    alert_router.escalation.add_contact(contact_obj)
    return {"ok": True, "contact": contact_dict}

@app.delete("/api/alerting/contacts/{contact_id}")
async def delete_oncall_contact(contact_id: str):
    ok = alert_router.escalation.delete_contact(contact_id)
    return {"ok": ok}

@app.get("/api/alerting/mappings")
async def list_ownership_mappings():
    return alert_router.queue.list_mappings()

class MappingPayload(BaseModel):
    cidr_or_host: str
    environment: str = "Production"
    owner_team: str = "SOC-Tier2"
    primary_contact_id: str
    escalation_contact_id: str
    escalation_timeout_mins: int = 5

@app.post("/api/alerting/mappings")
async def save_ownership_mapping(m: MappingPayload):
    from aegis.alerting.models import AssetOwnerMapping
    mapping_obj = AssetOwnerMapping(**m.model_dump())
    alert_router.escalation.add_owner_mapping(mapping_obj)
    return {"ok": True, "mapping": m.model_dump()}

@app.delete("/api/alerting/mappings/{cidr_or_host:path}")
async def delete_ownership_mapping(cidr_or_host: str):
    ok = alert_router.escalation.delete_mapping(cidr_or_host)
    return {"ok": ok}

class ChannelTestPayload(BaseModel):
    channel: str  # sms, telegram, whatsapp
    recipient: str

@app.post("/api/settings/test-channel")
async def test_dispatch_channel(req: ChannelTestPayload):
    """Sends an instant test alert message through the selected gateway to verify setup."""
    from aegis.alerting.models import CriticalAlert, SeverityLevel, OnCallContact
    dummy_contact = OnCallContact(
        contact_id="TEST-USER",
        name="Verification Test",
        phone=req.recipient,
        whatsapp_number=req.recipient,
        telegram_chat_id=req.recipient
    )
    dummy_alert = CriticalAlert(
        alert_id="CALT-TEST-VERIFY",
        fingerprint="TEST-FINGERPRINT",
        title="Aegis AI Gateway Setup Verification",
        severity=SeverityLevel.CRITICAL,
        summary="This is an automated verification test sent from Aegis AI Settings.",
        source_ip="127.0.0.1"
    )
    triage_url = f"{alert_router.base_console_url}/#settings"
    if req.channel == "sms":
        res = await alert_router.adapter_sms.send(dummy_alert, dummy_contact, triage_url)
    elif req.channel in ("telegram", "whatsapp", "webhook"):
        res = await alert_router.adapter_webhook.send(dummy_alert, dummy_contact, triage_url)
    else:
        raise HTTPException(status_code=400, detail="Unsupported test channel")
    return res.model_dump()


# ── Incident Containment & Machine Remediation ─────────────────────────────
class IncidentActionRequest(BaseModel):
    incident_id: str
    action_type: str  # terminate_process, block_ip, isolate_connections, resolve
    target: Optional[str] = None
    pid: Optional[int] = None
    note: Optional[str] = None


@app.post("/api/incidents/action")
async def execute_incident_action(req: IncidentActionRequest):
    """
    Executes real host-level remediation on machine processes or network firewall rules
    in response to an individual correlated alert incident.
    """
    inc = analyst.get_incident(req.incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{req.incident_id}' not found")

    res = None
    if req.action_type == "terminate_process":
        res = remediator.terminate_process(target=req.target or "", pid=req.pid)
    elif req.action_type == "block_ip":
        res = remediator.block_remote_ip(ip=req.target or "")
    elif req.action_type == "isolate_connections":
        res = remediator.isolate_socket_connections(remote_ip=req.target or "")
    elif req.action_type == "resolve":
        res = {
            "success": True,
            "message": f"Incident {req.incident_id} marked as contained and resolved.",
            "action": "resolve",
            "target": req.incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported action type '{req.action_type}'")

    if res.get("success"):
        inc.record_action(res)
    else:
        inc.record_action({"action": req.action_type, "success": False, "error": res.get("error", "Failed")})

    return res


@app.websocket("/ws/monitor")
async def ws_monitor(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            state = monitor.get_state()
            state["incidents"] = analyst.analyze(monitor.alerts)
            # Strip internal fields before sending
            for alert in state.get("alerts", []):
                alert.pop("_timestamp", None)
                alert.pop("_dedup_key", None)
            await websocket.send_json(state)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass


# ── WebSocket: real-time scan progress stream ───────────────────────────────
@app.websocket("/ws/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    last_sent = 0
    try:
        while True:
            if scan_id not in scans:
                await websocket.send_json({"type": "error", "message": "Scan not found"})
                break

            scan = scans[scan_id]
            log = scan.get("log", [])

            # Send any new log lines
            if len(log) > last_sent:
                for line in log[last_sent:]:
                    await websocket.send_json({"type": "log", "message": line})
                last_sent = len(log)

            # Send progress update
            await websocket.send_json({
                "type": "progress",
                "progress": scan.get("progress", 0),
                "status": scan.get("status"),
                "open_ports": scan.get("open_ports", []),
            })

            if scan["status"] in ("done", "error"):
                await websocket.send_json({
                    "type": "complete",
                    "scan": scans[scan_id]
                })
                break

            await asyncio.sleep(0.4)
    except WebSocketDisconnect:
        pass


# ── Internal: background scan runner ───────────────────────────────────────
async def _run_scan(scan_id: str, target: str, ports: List[int], concurrency: int):
    scan = scans[scan_id]

    def log(msg: str):
        scan["log"].append(msg)

    try:
        scan["status"] = "running"
        clean_host, custom_port = normalize_target(target)
        if clean_host and clean_host != target:
            log(f"[*] Normalized target '{target}' -> '{clean_host}'")
            target = clean_host
            scan["target"] = target
        if custom_port and custom_port not in ports:
            ports = [custom_port] + [p for p in ports if p != custom_port]
        log(f"[*] Starting scan of {target}")

        config = ScanConfig(
            target=target,
            ports=ports,
            concurrency=concurrency,
        )

        # Monkey-patch engine to push progress updates
        from aegis.discovery.port_scanner import AsyncPortScanner
        from aegis.discovery.fingerprint import ServiceFingerprinter
        from aegis.discovery.cpe_matcher import CPEMatcher
        from aegis.database.db import VulnerabilityDatabase
        from aegis.scoring.risk_engine import RiskPrioritizationEngine
        from aegis.core.models import HostScanResult, ScanReport, Finding, Severity
        from aegis.checks.http_checks import HTTPMisconfigChecker
        from aegis.checks.tls_auditor import TLSAuditor
        from aegis.checks.template_engine import TemplateEngine
        from aegis.checks.smb_checks import SMBAuditor
        from aegis.checks.dns_checks import DNSAuditor
        import socket as _socket

        # Step 1: Resolve
        log(f"[*] Resolving {target}...")
        scan["progress"] = 5
        try:
            ip = _socket.gethostbyname(target)
            log(f"[+] Resolved: {target} -> {ip}")
        except Exception:
            ip = target
            log(f"[!] Could not resolve, using raw IP: {ip}")

        # Step 2: Port scan
        log(f"[*] Scanning {len(ports)} ports (concurrency={concurrency})...")
        scan["progress"] = 10
        scanner = AsyncPortScanner(config)
        open_ports = await scanner.scan_target(ip, ports)
        scan["open_ports"] = open_ports
        scan["progress"] = 35
        log(f"[+] Open ports: {open_ports or 'None found'}")

        if not open_ports:
            log("[!] No open ports. Host may be offline or heavily filtered.")
            scan["status"] = "done"
            scan["progress"] = 100
            return

        # Step 3: Fingerprint
        log(f"[*] Fingerprinting {len(open_ports)} services...")
        scan["progress"] = 40
        fingerprinter = ServiceFingerprinter(config)
        fp_tasks = [fingerprinter.fingerprint(ip, p) for p in open_ports]
        services_raw = await asyncio.gather(*fp_tasks, return_exceptions=True)

        services = []
        for svc in services_raw:
            if isinstance(svc, Exception):
                continue
            if svc.product:
                svc.cpe = CPEMatcher.generate_cpe(svc.product, svc.version)
            services.append(svc)
            log(f"[+] Port {svc.port}/tcp: {svc.service_name.upper()} | {svc.product or '?'} {svc.version or ''}")

        scan["services"] = [s.model_dump() for s in services]
        scan["progress"] = 55

        # Step 4: CVE matching
        log("[*] Correlating with vulnerability database...")
        vdb = VulnerabilityDatabase(config.data_dir / "vdb.sqlite3")
        risk = RiskPrioritizationEngine()
        findings = []

        for svc in services:
            if not svc.product:
                continue
            from aegis.discovery.cpe_matcher import CPE_LOOKUP
            if svc.cpe:
                _, vendor, product, _ = CPEMatcher.parse_cpe(svc.cpe)
            else:
                prod = svc.product.lower()
                vendor, product = CPE_LOOKUP.get(prod, (prod, prod))

            vulns = vdb.query_vulnerabilities(vendor, product, svc.version)
            for vuln in vulns:
                f = Finding(
                    id=vuln.id, title=vuln.title, target=target,
                    port=svc.port, service=svc.service_name,
                    severity=vuln.severity, cvss_score=vuln.cvss_score,
                    epss_score=vuln.epss_score, is_cisa_kev=vuln.is_cisa_kev,
                    description=vuln.description,
                    evidence=f"Detected {svc.product} {svc.version or '?'} on port {svc.port}",
                    remediation=vuln.remediation,
                    cve_id=vuln.id if vuln.id.startswith("CVE-") else None,
                    references=vuln.references,
                )
                f = risk.prioritize_finding(f)
                findings.append(f)
                log(f"[!] CVE match: {vuln.id} on port {svc.port} (score={f.composite_risk_score})")

        scan["progress"] = 65

        # Step 5: HTTP checks
        log("[*] Running HTTP security checks...")
        host_result = HostScanResult(host=target, ip=ip, open_ports=open_ports, services=services)
        http_svcs = [s for s in services if s.service_name in ("http", "https")]
        for svc in http_svcs:
            checker = HTTPMisconfigChecker(config)
            hf = await checker.check(target, svc.port, svc.tls)
            findings.extend(hf)
            log(f"[*] HTTP checks on port {svc.port}: {len(hf)} findings")

        scan["progress"] = 75

        # Step 6: TLS checks
        log("[*] Running TLS/SSL deep audit...")
        tls_svcs = [s for s in services if s.tls or s.port in (443, 8443)]
        for svc in tls_svcs:
            tls = TLSAuditor(config)
            tf = await tls.audit(ip, svc.port)
            findings.extend(tf)
            log(f"[*] TLS checks on port {svc.port}: {len(tf)} findings")

        scan["progress"] = 85

        # Step 7: YAML templates
        log("[*] Running declarative detection templates...")
        te = TemplateEngine(config)
        if te.templates:
            tf2 = await te.run_all(ip, open_ports)
            findings.extend(tf2)
            log(f"[*] Templates: {len(tf2)} findings from {len(te.templates)} checks")

        scan["progress"] = 88

        # Step 8: SMB checks
        log("[*] Running SMB security checks...")
        smb_svcs = [s for s in services if s.service_name in ("smb", "microsoft-ds", "netbios-ssn") or s.port in (139, 445)]
        for svc in smb_svcs:
            smb = SMBAuditor(config)
            sf = await smb.audit(target, svc.port)
            findings.extend(sf)
            log(f"[*] SMB checks on port {svc.port}: {len(sf)} findings")

        scan["progress"] = 91

        # Step 9: DNS checks
        log("[*] Running DNS security checks...")
        dns_svcs = [s for s in services if s.service_name == "dns" or s.port == 53]
        for svc in dns_svcs:
            dns = DNSAuditor(config)
            df = await dns.audit(target, svc.port)
            findings.extend(df)
            log(f"[*] DNS checks on port {svc.port}: {len(df)} findings")

        scan["progress"] = 95

        # Finalize
        findings.sort(key=lambda f: f.composite_risk_score, reverse=True)
        scan["findings"] = [f.model_dump(mode="json") for f in findings]
        # Critical alert routing for weaponized KEV findings
        try:
            for f in findings:
                if f.is_cisa_kev or f.composite_risk_score >= 80:
                    asyncio.create_task(alert_router.route_scan_finding(target, f.model_dump(mode="json")))
        except Exception:
            pass
        scan["total_findings"] = len(findings)

        breakdown = {s.value: 0 for s in Severity}
        for f in findings:
            breakdown[f.severity.value] += 1
        scan["severity_breakdown"] = breakdown

        from datetime import datetime as dt
        started = datetime.fromisoformat(scan["started_at"])
        scan["duration"] = round((dt.utcnow() - started).total_seconds(), 1)
        scan["status"] = "done"
        scan["progress"] = 100
        log(f"[+] Scan complete. {len(findings)} findings in {scan['duration']}s.")

    except Exception as e:
        scan["status"] = "error"
        scan["log"].append(f"[!] Fatal error: {e}")
        scan["progress"] = 100


async def _run_update():
    db = VulnerabilityDatabase()
    syncer = ThreatFeedSync(db)
    try:
        await syncer.sync_all()
    except Exception as e:
        print(f"[!] Error during threat feed synchronization: {e}")
