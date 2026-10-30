"""Apply and roll back host containment. Never report a block that did not happen."""

from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aegis.monitor.remediation import PROTECTED_PROCESS_NAMES, remediator


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def contain_platform() -> str:
    override = os.getenv("AEGIS_CONTAIN_PLATFORM", "").strip().lower()
    if override:
        return override
    return (platform.system() or "").strip().lower()


def _valid_ip(value: str) -> Optional[str]:
    text = (value or "").strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return None
    return text


def firewall_commands(action: str, target: str, action_id: str = "") -> Dict[str, List[str]]:
    """Return apply/rollback command strings for the current platform. Dry-run uses these."""
    system = contain_platform()
    tag = (action_id or target or "aegis").replace(":", "_")[:48]
    if action in {"block_ip", "unblock_ip"}:
        ip = target
        if system.startswith("win"):
            out_name = f"Aegis_Block_Out_{ip.replace(':', '_')}"
            in_name = f"Aegis_Block_In_{ip.replace(':', '_')}"
            apply_cmds = [
                f'netsh advfirewall firewall add rule name="{out_name}" dir=out action=block remoteip={ip}',
                f'netsh advfirewall firewall add rule name="{in_name}" dir=in action=block remoteip={ip}',
            ]
            rollback_cmds = [
                f'netsh advfirewall firewall delete rule name="{out_name}"',
                f'netsh advfirewall firewall delete rule name="{in_name}"',
            ]
        else:
            comment = f"AEGIS-RSP:{tag}"
            apply_cmds = [
                f"iptables -I OUTPUT -d {ip} -m comment --comment {comment} -j DROP",
                f"iptables -I INPUT -s {ip} -m comment --comment {comment} -j DROP",
            ]
            rollback_cmds = [
                f"iptables -D OUTPUT -d {ip} -m comment --comment {comment} -j DROP",
                f"iptables -D INPUT -s {ip} -m comment --comment {comment} -j DROP",
            ]
        if action == "unblock_ip":
            return {"apply": rollback_cmds, "rollback": apply_cmds}
        return {"apply": apply_cmds, "rollback": rollback_cmds}

    if action in {"quarantine_host", "unquarantine_host"}:
        if system.startswith("win"):
            out_name = f"Aegis_Quarantine_Out_{tag}"
            in_name = f"Aegis_Quarantine_In_{tag}"
            apply_cmds = [
                f'netsh advfirewall firewall add rule name="{out_name}" dir=out action=block',
                f'netsh advfirewall firewall add rule name="{in_name}" dir=in action=block',
            ]
            rollback_cmds = [
                f'netsh advfirewall firewall delete rule name="{out_name}"',
                f'netsh advfirewall firewall delete rule name="{in_name}"',
            ]
        else:
            comment = f"AEGIS-Q:{tag}"
            apply_cmds = [
                f"iptables -I OUTPUT -m comment --comment {comment} -j DROP",
                f"iptables -I INPUT -m comment --comment {comment} -j DROP",
            ]
            rollback_cmds = [
                f"iptables -D OUTPUT -m comment --comment {comment} -j DROP",
                f"iptables -D INPUT -m comment --comment {comment} -j DROP",
            ]
        if action == "unquarantine_host":
            return {"apply": rollback_cmds, "rollback": apply_cmds}
        return {"apply": apply_cmds, "rollback": rollback_cmds}

    if action == "terminate_process":
        clean = os.path.basename(target).strip()
        return {"apply": [f"taskkill /F /IM {clean}" if system.startswith("win") else f"pkill -x {clean}"], "rollback": []}

    if action == "isolate_connections":
        return {"apply": [f"close sockets involving {target}"], "rollback": []}

    return {"apply": [], "rollback": []}


def preview_diff(action: str, target: str, action_id: str = "") -> Dict[str, Any]:
    cmds = firewall_commands(action, target, action_id=action_id)
    system = contain_platform()
    rollback_possible = action in {"block_ip", "unblock_ip", "quarantine_host", "unquarantine_host"}
    labels = {
        "block_ip": f"Add host firewall rules that drop traffic to {target}",
        "unblock_ip": f"Remove host firewall rules that drop traffic to {target}",
        "quarantine_host": "Add host firewall rules that isolate this host",
        "unquarantine_host": "Remove host isolation firewall rules on this host",
        "terminate_process": f"Terminate running instances of '{target}' on this host",
        "isolate_connections": f"Terminate processes holding sockets involving {target}",
    }
    return {
        "dry_run": True,
        "mutates": False,
        "platform": system,
        "would": labels.get(action, f"Would run {action} on {target}. Not executed."),
        "commands": list(cmds.get("apply") or []),
        "rollback_commands": list(cmds.get("rollback") or []),
        "rollback_possible": rollback_possible,
        "applied": False,
    }


def _run_shell(command: str, timeout: float = 8.0) -> Dict[str, Any]:
    system = contain_platform()
    if system.startswith("win"):
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=True)
    else:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, shell=True)
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": stdout[:400],
        "stderr": stderr[:400],
        "ok": completed.returncode == 0,
    }


class HostExecutor:
    """Mutates this host. applied is True only when the OS accepted the change."""

    def apply(self, action: str, target: str, action_id: str = "", dry_run: bool = False) -> Dict[str, Any]:
        action = (action or "").strip()
        target = (target or "").strip()
        diff = preview_diff(action, target, action_id=action_id)
        base = {
            "action": action,
            "target": target,
            "action_id": action_id,
            "timestamp": _now(),
            "platform": diff["platform"],
            "dry_run": bool(dry_run),
            "mutates": not dry_run,
            "applied": False,
            "staged": False,
            "success": False,
            "commands": diff["commands"],
            "rollback_commands": diff["rollback_commands"],
            "rollback_possible": diff["rollback_possible"],
            "would": diff["would"],
        }
        if action in {"block_ip", "unblock_ip"}:
            if not _valid_ip(target):
                return {**base, "error": f"Refusing {action} for invalid or loopback address '{target}'."}
        if action == "terminate_process":
            clean = os.path.basename(target).strip()
            if not clean:
                return {**base, "error": "No process name specified."}
            if clean.lower() in PROTECTED_PROCESS_NAMES:
                return {**base, "error": f"Refusing to terminate protected process '{clean}'."}
        if dry_run:
            return {**base, "message": diff["would"] + " Not executed."}

        if action in {"block_ip", "unblock_ip", "quarantine_host", "unquarantine_host"}:
            return self._apply_firewall(action, target, action_id, base)
        if action == "terminate_process":
            return self._apply_terminate(target, base)
        if action == "isolate_connections":
            return self._apply_isolate(target, base)
        return {**base, "error": f"Unsupported action '{action}'"}

    def rollback(self, action: str, target: str, action_id: str = "", dry_run: bool = False) -> Dict[str, Any]:
        inverse = {
            "block_ip": "unblock_ip",
            "unblock_ip": "block_ip",
            "quarantine_host": "unquarantine_host",
            "unquarantine_host": "quarantine_host",
        }.get(action)
        if not inverse:
            diff = preview_diff(action, target, action_id=action_id)
            return {
                "action": action,
                "target": target,
                "applied": False,
                "success": False,
                "dry_run": bool(dry_run),
                "rollback_possible": False,
                "error": f"No rollback for '{action}'. Process kill and socket isolate are not reversible.",
                "would": diff.get("would"),
                "commands": [],
            }
        return self.apply(inverse, target, action_id=action_id, dry_run=dry_run)

    def _apply_firewall(self, action: str, target: str, action_id: str, base: Dict[str, Any]) -> Dict[str, Any]:
        system = contain_platform()
        if not system.startswith("win"):
            if not shutil.which("iptables"):
                return {
                    **base,
                    "error": "iptables is not on this host. Firewall change was not applied.",
                }
        runs = []
        ok = True
        for command in base["commands"]:
            try:
                result = _run_shell(command)
            except Exception as exc:
                result = {"command": command, "ok": False, "error": str(exc), "returncode": -1}
            runs.append(result)
            if not result.get("ok"):
                ok = False
                break
        if ok:
            return {
                **base,
                "applied": True,
                "success": True,
                "runs": runs,
                "message": f"Applied {action} on this host for {target}.",
            }
        hint = "Administrator privileges required." if system.startswith("win") else "root privileges required."
        err = runs[-1].get("stderr") or runs[-1].get("error") or "command failed"
        return {
            **base,
            "applied": False,
            "success": False,
            "runs": runs,
            "error": f"{action} was not applied ({err}). {hint}",
        }

    def _apply_terminate(self, target: str, base: Dict[str, Any]) -> Dict[str, Any]:
        result = remediator.terminate_process(target=target)
        pids = result.get("terminated_pids") or []
        staged = bool(result.get("staged_file"))
        applied = bool(pids)
        message = result.get("message") or ""
        if staged and not applied:
            message = (
                f"Process '{target}' was not terminated. "
                "A staged admin script is not an applied contain."
            )
        return {
            **base,
            "applied": applied,
            "success": applied,
            "staged": staged and not applied,
            "terminated_pids": pids,
            "message": message if applied else (result.get("error") or message or "Process was not terminated."),
            "error": None if applied else (result.get("error") or message or "Process was not terminated."),
        }

    def _apply_isolate(self, target: str, base: Dict[str, Any]) -> Dict[str, Any]:
        result = remediator.isolate_socket_connections(remote_ip=target)
        pids = result.get("terminated_pids") or []
        staged = bool(result.get("staged_pids"))
        applied = bool(pids)
        if not applied:
            return {
                **base,
                "applied": False,
                "success": False,
                "staged": staged,
                "terminated_pids": pids,
                "error": (
                    result.get("error")
                    or f"No sockets to {target} were closed on this host. Isolation was not applied."
                ),
            }
        return {
            **base,
            "applied": True,
            "success": True,
            "staged": False,
            "terminated_pids": pids,
            "message": result.get("message") or f"Closed sockets to {target}.",
        }
