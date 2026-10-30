#!/usr/bin/env python3
"""Part 3.5: build a real incident narrative from synthetic alerts through AIAnalyst.analyze."""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "13_ai_narrative.json"

from aegis.monitor.ai_analyst import AIAnalyst

now = time.time()
alerts = [
    {
        "id": "ALT-0001",
        "pattern_id": "AEGIS-BEH-002",
        "severity": "CRITICAL",
        "title": "C2 Beaconing Detected: 10.0.0.8 → 203.0.113.50",
        "source_ip": "10.0.0.8",
        "dest_ip": "203.0.113.50",
        "dest_port": 443,
        "process": "svchost.exe",
        "evidence": "Interval: 30.1s ± 0.4s over 8 connections",
        "tactic": "Command and Control",
        "technique": "T1071",
        "_timestamp": now - 20,
    },
    {
        "id": "ALT-0002",
        "pattern_id": "AEGIS-BEH-010",
        "severity": "CRITICAL",
        "title": "SMB Lateral Movement from 10.0.0.8",
        "source_ip": "10.0.0.8",
        "dest_ip": "multiple internal",
        "dest_port": 445,
        "process": "psexesvc.exe",
        "evidence": "SMB (port 445) connections to 5 unique hosts from 10.0.0.8",
        "tactic": "Lateral Movement",
        "technique": "T1021.002",
        "_timestamp": now - 10,
    },
    {
        "id": "ALT-0003",
        "pattern_id": "AEGIS-BEH-001",
        "severity": "HIGH",
        "title": "Port Scan Detected from 10.0.0.8",
        "source_ip": "10.0.0.8",
        "dest_ip": "multiple",
        "dest_port": 0,
        "process": "",
        "evidence": "Unique ports contacted: 22 | Sample ports: [22, 80, 443]",
        "tactic": "Discovery",
        "technique": "T1046",
        "_timestamp": now - 5,
    },
]

analyst = AIAnalyst()
incidents = analyst.analyze(alerts)
payload = {
    "ml_imports_in_ai_analyst": False,
    "grouping": "by source_ip, then cluster if consecutive _timestamp delta <= CORRELATION_WINDOW (600s)",
    "scoring": "confidence = min(len(alerts)*15,60) + min(crit*10,25) + min(n_tactics*5,15)",
    "n_incidents": len(incidents),
    "incidents": incidents,
}
OUT.write_text(json.dumps(payload, indent=2, default=str))
print(json.dumps(payload, indent=2, default=str))
