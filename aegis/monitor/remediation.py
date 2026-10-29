"""
Aegis AI — Remediation & Containment Engine.

Executes real host-level security actions in response to correlated incidents:
- Process termination (killing suspicious or rogue executables)
- Host/IP firewall blocking (via Windows Defender Firewall netsh rules)
- Socket connection isolation
- Incident containment auditing
"""

import os
import sys
import time
import psutil
import tempfile
import ipaddress
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Protected core system processes that must never be terminated
PROTECTED_PROCESS_NAMES = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "fontdrvhost.exe", "spoolsv.exe", "winlogon.exe"
}

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PENDING_BAT_PATH = os.path.join(WORKSPACE_DIR, "enforce_pending_containment.bat")


def is_running_as_admin() -> bool:
    """Checks if the current Python process has High integrity / Administrator privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def append_to_enforce_script(commands: List[str], desc: str = ""):
    """
    Appends containment commands to a clean batch file in the workspace
    so the user can right-click -> Run as Administrator to enforce all staged rules.
    """
    try:
        header_needed = not os.path.exists(PENDING_BAT_PATH) or os.path.getsize(PENDING_BAT_PATH) == 0
        with open(PENDING_BAT_PATH, "a", encoding="utf-8") as f:
            if header_needed:
                f.write("@echo off\r\n")
                f.write("title Aegis AI - Containment Enforcer\r\n")
                f.write("cd /d \"%~dp0\"\r\n")
                f.write("net session >nul 2>&1\r\n")
                f.write("if %errorlevel% neq 0 (\r\n")
                f.write("    echo =====================================================================\r\n")
                f.write("    echo  [!] ADMINISTRATOR PRIVILEGES REQUIRED\r\n")
                f.write("    echo =====================================================================\r\n")
                f.write("    echo  Please right-click this file and select 'Run as Administrator'\r\n")
                f.write("    echo  or launch Aegis via 'start_aegis_admin.bat'.\r\n")
                f.write("    echo =====================================================================\r\n")
                f.write("    echo.\r\n")
                f.write("    pause\r\n")
                f.write("    exit /b 1\r\n")
                f.write(")\r\n")
                f.write("echo =====================================================================\r\n")
                f.write("echo  AEGIS AI - EXECUTING HOST CONTAINMENT ACTIONS\r\n")
                f.write("echo =====================================================================\r\n")
                f.write("echo.\r\n")

            if desc:
                f.write(f"echo [*] {desc}\r\n")
            for c in commands:
                f.write(f"echo Executing: {c}\r\n")
                f.write(f"{c}\r\n")
            f.write("echo.\r\n")
            f.write("echo [OK] Containment actions successfully enforced.\r\n")
            f.write("timeout /t 3 >nul\r\n")
    except Exception:
        pass


class RemediationEngine:
    """Executes local machine containment and remediation actions."""

    def __init__(self):
        self.action_history: List[Dict[str, Any]] = []

    def terminate_process(self, target: str, pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Terminates one or all running instances of a process by name or PID.
        Guards against terminating core Windows system processes or the server itself.
        """
        current_pid = os.getpid()
        terminated_pids = []
        errors = []
        access_denied = False

        if pid is not None:
            if pid == current_pid:
                return {
                    "success": False,
                    "error": "Cannot terminate the Aegis AI server process itself."
                }
            try:
                p = psutil.Process(pid)
                p_name = p.name().lower()
                if p_name in PROTECTED_PROCESS_NAMES:
                    return {
                        "success": False,
                        "error": f"Refusing to terminate protected system process '{p_name}' (PID: {pid})."
                    }
                p.terminate()
                try:
                    p.wait(timeout=1.5)
                except psutil.TimeoutExpired:
                    p.kill()
                terminated_pids.append(pid)
            except psutil.NoSuchProcess:
                return {"success": False, "error": f"PID {pid} is no longer running."}
            except psutil.AccessDenied:
                access_denied = True
            except Exception as e:
                return {"success": False, "error": f"Failed to terminate PID {pid}: {str(e)}"}
        else:
            clean_name = os.path.basename(target).strip().lower()
            if not clean_name:
                return {"success": False, "error": "No process name specified."}

            if clean_name in PROTECTED_PROCESS_NAMES:
                return {
                    "success": False,
                    "error": f"Refusing to terminate protected system process '{clean_name}'."
                }

            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    p_info_name = (proc.info.get('name') or '').lower()
                    p_pid = proc.info.get('pid')
                    if p_pid == current_pid:
                        continue
                    if p_info_name == clean_name or p_info_name == clean_name + '.exe':
                        proc.terminate()
                        try:
                            proc.wait(timeout=1.5)
                        except psutil.TimeoutExpired:
                            proc.kill()
                        terminated_pids.append(p_pid)
                except psutil.AccessDenied:
                    access_denied = True
                    continue
                except (psutil.NoSuchProcess, Exception):
                    continue

        now_iso = datetime.now(timezone.utc).isoformat()
        if terminated_pids:
            msg = f"Terminated {len(terminated_pids)} process instance(s) of '{target}' (PIDs: {terminated_pids})"
            res = {
                "success": True,
                "message": msg,
                "action": "terminate_process",
                "target": target,
                "terminated_pids": terminated_pids,
                "timestamp": now_iso
            }
            self.action_history.append(res)
            return res
        elif access_denied:
            clean_target = os.path.basename(target).strip()
            kill_cmd = f"taskkill /F /PID {pid}" if pid else f"taskkill /F /IM {clean_target}"
            append_to_enforce_script([kill_cmd], desc=f"Terminate rogue process {clean_target}")
            msg = f"Terminating '{clean_target}' requires Administrator privileges. Launch Aegis via 'start_aegis_admin.bat' for 1-click in-browser enforcement."
            res = {
                "success": True,
                "message": msg,
                "action": "terminate_process",
                "target": target,
                "staged_file": PENDING_BAT_PATH,
                "timestamp": now_iso
            }
            self.action_history.append(res)
            return res
        elif errors:
            return {"success": False, "error": f"Failed: {', '.join(errors)}"}
        else:
            return {"success": False, "error": f"No active process matching '{target}' found running."}

    def block_remote_ip(self, ip: str) -> Dict[str, Any]:
        """
        Blocks inbound and outbound traffic to a remote IP via Windows Defender Firewall.
        When running as Administrator, enforces immediately with zero prompts.
        When running without Administrator, stages into the containment batch file.
        """
        clean_ip = ip.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_loopback or ip_obj.is_unspecified:
                return {"success": False, "error": f"Refusing to block loopback or invalid address '{clean_ip}'."}
        except ValueError:
            return {"success": False, "error": f"Invalid IP address format: '{clean_ip}'."}

        rule_name_out = f"Aegis_Block_Out_{clean_ip.replace(':', '_')}"
        rule_name_in = f"Aegis_Block_In_{clean_ip.replace(':', '_')}"

        cmd_out = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name_out}", "dir=out", "action=block",
            f"remoteip={clean_ip}"
        ]
        cmd_in = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name_in}", "dir=in", "action=block",
            f"remoteip={clean_ip}"
        ]

        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: Direct execution (works immediately when server runs with Administrator rights)
        try:
            r_out = subprocess.run(cmd_out, capture_output=True, text=True, timeout=5)
            if r_out.returncode == 0 or "Ok" in r_out.stdout or "already exists" in r_out.stderr.lower():
                subprocess.run(cmd_in, capture_output=True, text=True, timeout=5)
                msg = f"Created Windows Firewall rule: blocked all communication with {clean_ip}"
                res = {
                    "success": True,
                    "message": msg,
                    "action": "block_ip",
                    "target": clean_ip,
                    "rule_name": rule_name_out,
                    "timestamp": now_iso
                }
                self.action_history.append(res)
                return res
        except Exception:
            pass

        # Step 2: If server is running without Administrator rights, stage command cleanly
        cmd_out_str = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out action=block remoteip={clean_ip}'
        cmd_in_str = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in action=block remoteip={clean_ip}'
        append_to_enforce_script([cmd_out_str, cmd_in_str], desc=f"Block IP {clean_ip} (Inbound + Outbound)")

        msg = f"Rule staged in 'enforce_pending_containment.bat'. To enforce with 1 click directly in browser, right-click 'start_aegis_admin.bat' -> Run as Administrator."
        res = {
            "success": True,
            "message": msg,
            "action": "block_ip",
            "target": clean_ip,
            "rule_name": rule_name_out,
            "staged_file": PENDING_BAT_PATH,
            "timestamp": now_iso
        }
        self.action_history.append(res)
        return res

    def isolate_socket_connections(self, remote_ip: str) -> Dict[str, Any]:
        """
        Finds any open TCP socket to the specified remote IP and terminates the connection's owner.
        """
        clean_ip = remote_ip.strip()
        current_pid = os.getpid()
        killed_pids = []
        denied_pids = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and getattr(conn.raddr, 'ip', None) == clean_ip:
                    pid = conn.pid
                    if pid and pid != current_pid and pid not in killed_pids:
                        try:
                            p = psutil.Process(pid)
                            if p.name().lower() not in PROTECTED_PROCESS_NAMES:
                                p.terminate()
                                killed_pids.append(pid)
                        except psutil.AccessDenied:
                            denied_pids.append(pid)
                        except (psutil.NoSuchProcess, Exception):
                            pass

            now_iso = datetime.now(timezone.utc).isoformat()
            if denied_pids:
                cmds = [f"taskkill /F /PID {p}" for p in denied_pids]
                append_to_enforce_script(cmds, desc=f"Isolate sockets to {clean_ip}")
                msg = f"Closed active sockets to {clean_ip} (PIDs {killed_pids}). Elevated termination staged for PIDs: {denied_pids}."
                res = {
                    "success": True,
                    "message": msg,
                    "action": "isolate_connections",
                    "target": clean_ip,
                    "terminated_pids": killed_pids,
                    "staged_pids": denied_pids,
                    "timestamp": now_iso
                }
                self.action_history.append(res)
                return res
            elif killed_pids:
                msg = f"Closed active socket sessions to {clean_ip} by terminating PIDs: {killed_pids}"
                res = {
                    "success": True,
                    "message": msg,
                    "action": "isolate_connections",
                    "target": clean_ip,
                    "terminated_pids": killed_pids,
                    "timestamp": now_iso
                }
                self.action_history.append(res)
                return res
            else:
                return {
                    "success": True,
                    "message": f"No active socket connections found targeting {clean_ip} (already closed or dormant).",
                    "action": "isolate_connections",
                    "target": clean_ip,
                    "terminated_pids": [],
                    "timestamp": now_iso
                }
        except Exception as e:
            return {"success": False, "error": f"Socket inspection error: {str(e)}"}


# Global singleton instance
remediator = RemediationEngine()
