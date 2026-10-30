#!/usr/bin/env python3
"""Part 3.8: what Windows-only calls do on this Linux host."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent / "results" / "16_windows_linux.json"

from aegis.monitor.remediation import is_running_as_admin, remediator

admin = is_running_as_admin()

# netsh
try:
    r = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                       capture_output=True, text=True, timeout=5)
    netsh = {"returncode": r.returncode, "stdout_trim": r.stdout[:200], "stderr_trim": r.stderr[:200]}
except Exception as e:
    netsh = {"error": repr(e)}

# taskkill
try:
    r = subprocess.run(["taskkill"], capture_output=True, text=True, timeout=5)
    taskkill = {"returncode": r.returncode, "stdout_trim": r.stdout[:200], "stderr_trim": r.stderr[:200]}
except Exception as e:
    taskkill = {"error": repr(e)}

# ctypes.windll
windll = None
try:
    import ctypes
    windll = {"has_windll": hasattr(ctypes, "windll")}
    if hasattr(ctypes, "windll"):
        try:
            windll["IsUserAnAdmin"] = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception as e:
            windll["IsUserAnAdmin_error"] = repr(e)
except Exception as e:
    windll = {"error": repr(e)}

# COM3
com3_exists = os.path.exists("/dev/ttyUSB0") or os.path.exists("COM3")

# Exercise remediator.block_remote_ip on a TEST-NET IP (documentation range)
block_res = remediator.block_remote_ip("192.0.2.1")
# terminate a definitely-not-running process name
term_res = remediator.terminate_process("definitely_not_a_real_aegis_audit_proc.exe")
iso_res = remediator.isolate_socket_connections("192.0.2.1")

payload = {
    "platform": sys.platform,
    "is_running_as_admin": admin,
    "windll": windll,
    "netsh": netsh,
    "taskkill": taskkill,
    "com3_or_ttyusb0_exists": com3_exists,
    "block_remote_ip_192.0.2.1": block_res,
    "terminate_missing_process": term_res,
    "isolate_192.0.2.1": iso_res,
    "pending_bat_created": os.path.exists(str(ROOT / "enforce_pending_containment.bat")),
}
# Remove the bat if the remediator created it during this audit — that's a side effect.
# Spec: do not modify existing files; a newly created bat is a measurement side effect.
# Leave it; report the path. User/coordinator can delete. Do NOT delete product files.
OUT.write_text(json.dumps(payload, indent=2, default=str))
print(json.dumps(payload, indent=2, default=str))
