#!/usr/bin/env python3
"""Part 1.3: hit every GET endpoint; never print admin token."""
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import httpx

BASE = os.environ.get("AEGIS_AUDIT_BASE", "http://127.0.0.1:8765")
OUT = Path(__file__).resolve().parent / "results" / "08_gets.json"
TOKEN_PATH = Path.home() / ".aegis" / "admin_token"


def json_shape(obj: Any, depth=0):
    if depth > 4:
        return "..."
    if obj is None:
        return None
    if isinstance(obj, bool):
        return "bool"
    if isinstance(obj, int):
        return "int"
    if isinstance(obj, float):
        return "float"
    if isinstance(obj, str):
        return "str"
    if isinstance(obj, list):
        if not obj:
            return []
        return [json_shape(obj[0], depth + 1)]
    if isinstance(obj, dict):
        return {k: json_shape(v, depth + 1) for k, v in obj.items()}
    return type(obj).__name__


def headers():
    h = {}
    if TOKEN_PATH.exists():
        tok = TOKEN_PATH.read_text().strip()
        if tok:
            h["Authorization"] = f"Bearer {tok}"
            h["X-Aegis-Token"] = tok
            h["X-Admin-Token"] = tok
    return h


def hit(client, method, path, **kw):
    t0 = time.perf_counter()
    try:
        resp = client.request(method, path, **kw)
        dt_ms = (time.perf_counter() - t0) * 1000
        body = resp.text
        shape = None
        parsed = None
        try:
            parsed = resp.json()
            shape = json_shape(parsed)
        except Exception:
            shape = {"non_json": True, "content_type": resp.headers.get("content-type"), "len": len(body)}
        return {
            "path": path,
            "method": method,
            "status": resp.status_code,
            "elapsed_ms": dt_ms,
            "shape": shape,
            "error": None,
        }
    except Exception as e:
        return {
            "path": path,
            "method": method,
            "status": None,
            "elapsed_ms": (time.perf_counter() - t0) * 1000,
            "shape": None,
            "error": repr(e),
        }


def main():
    used_token = TOKEN_PATH.exists() and bool(TOKEN_PATH.read_text().strip())
    gets = [
        "/",
        "/api/scans",
        "/api/scans/DOESNOTEXIST",
        "/api/scans/DOESNOTEXIST/download/html",
        "/api/scans/DOESNOTEXIST/download/csv",
        "/api/scans/DOESNOTEXIST/download/sarif",
        "/api/scans/DOESNOTEXIST/download/json",
        "/api/findings/instructions?finding_id=CVE-1&title=t&target=127.0.0.1&port=80",
        "/api/intelligence",
        "/api/threat/feeds",
        "/api/monitor",
        "/api/monitor/targets",
        "/api/alerting/status",
        "/api/alerting/alerts",
        "/api/alerting/triage/invalidtoken",
        "/api/settings",
        "/api/alerting/contacts",
        "/api/alerting/mappings",
        "/static/index.html",
        "/docs",
        "/openapi.json",
    ]
    results = []
    with httpx.Client(base_url=BASE, timeout=15.0, follow_redirects=True, headers=headers()) as client:
        boot = hit(client, "GET", "/")
        results.append(boot)
        for p in gets[1:]:
            results.append(hit(client, "GET", p))
        # also without extra auth headers if token was used, to see if required
        if used_token:
            with httpx.Client(base_url=BASE, timeout=15.0, follow_redirects=True) as naked:
                results.append({**hit(naked, "GET", "/api/monitor"), "note": "no_token"})
                results.append({**hit(naked, "GET", "/api/settings"), "note": "no_token"})

    payload = {
        "base": BASE,
        "admin_token_file_present": TOKEN_PATH.exists(),
        "admin_token_used": used_token,
        "token_not_printed": True,
        "results": results,
    }
    OUT.write_text(json.dumps(payload, indent=2, default=str))
    print(json.dumps(payload, indent=2, default=str))


if __name__ == "__main__":
    main()
