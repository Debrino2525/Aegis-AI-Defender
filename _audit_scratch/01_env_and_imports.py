#!/usr/bin/env python3
"""Part 1: environment, pip leftovers, import-time warnings."""
import json
import os
import platform
import sys
import traceback
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "01_env.json"

caught = []


def warn_hook(message, category, filename, lineno, file=None, line=None):
    caught.append({
        "category": category.__name__,
        "message": str(message),
        "filename": filename,
        "lineno": lineno,
    })


warnings.simplefilter("always")
warnings.showwarning = warn_hook

modules = [
    "server",
    "run",
    "aegis.monitor.network_monitor",
    "aegis.monitor.behavioral_engine",
    "aegis.monitor.threat_patterns",
    "aegis.monitor.ai_analyst",
    "aegis.monitor.remediation",
    "aegis.discovery.port_scanner",
    "aegis.discovery.fingerprint",
    "aegis.discovery.cpe_matcher",
    "aegis.database.db",
    "aegis.database.sync",
    "aegis.database.matcher",
    "aegis.alerting.router",
    "aegis.alerting.heartbeat",
    "aegis.alerting.classifier",
    "aegis.core.engine",
    "aegis.credentialed.ssh_auditor",
    "aegis.checks.template_engine",
    "aegis.scoring.risk_engine",
]

import_results = []
for name in modules:
    try:
        __import__(name)
        import_results.append({"module": name, "ok": True, "error": None})
    except Exception:
        import_results.append({
            "module": name,
            "ok": False,
            "error": traceback.format_exc(),
        })

# Trigger FastAPI app construction warnings by accessing server.app
try:
    import server as srv
    _ = srv.app
    routes = []
    for r in srv.app.routes:
        methods = sorted(getattr(r, "methods", []) or [])
        routes.append({
            "path": getattr(r, "path", str(r)),
            "name": getattr(r, "name", ""),
            "methods": methods,
        })
except Exception:
    routes = [{"error": traceback.format_exc()}]

payload = {
    "python_version": sys.version,
    "python_version_info": list(sys.version_info),
    "platform": platform.platform(),
    "os_uname": list(os.uname()),
    "executable": sys.executable,
    "cwd": os.getcwd(),
    "admin_token_exists": os.path.exists(os.path.expanduser("~/.aegis/admin_token")),
    "import_results": import_results,
    "warnings": caught,
    "routes": routes,
}
OUT.write_text(json.dumps(payload, indent=2, default=str))
print(json.dumps(payload, indent=2, default=str))
