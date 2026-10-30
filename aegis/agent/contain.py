"""Apply queued contain commands on the agent host. Honest applied flags only."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.response.executor import HostExecutor


def _agent_root(root: Optional[Path] = None) -> Path:
    if root is not None:
        return root
    from aegis.agent.client import agent_dir
    return agent_dir()


def results_path(root: Optional[Path] = None) -> Path:
    return _agent_root(root) / "command_results.json"


def load_pending_results(root: Optional[Path] = None) -> List[Dict[str, Any]]:
    path = results_path(root)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return data if isinstance(data, list) else []


def save_pending_results(rows: List[Dict[str, Any]], root: Optional[Path] = None) -> None:
    path = results_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2, default=str) + "\n", encoding="utf-8")


def clear_pending_results(root: Optional[Path] = None) -> None:
    path = results_path(root)
    try:
        path.unlink()
    except OSError:
        pass


def execute_commands(
    commands: List[Dict[str, Any]],
    executor: Optional[HostExecutor] = None,
    root: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Run each command on this host and remember the results for the next heartbeat."""
    host = executor or HostExecutor()
    pending = load_pending_results(root)
    for command in commands or []:
        if not isinstance(command, dict):
            continue
        kind = str(command.get("kind") or "")
        target = str(command.get("target") or "")
        action_id = str(command.get("action_id") or "")
        dry_run = bool(command.get("dry_run"))
        result = host.apply(kind, target, action_id=action_id, dry_run=dry_run)
        pending.append({
            "command_id": command.get("command_id"),
            "action_id": action_id,
            "applied": bool(result.get("applied")),
            "success": bool(result.get("applied")),
            "message": result.get("message"),
            "error": result.get("error"),
            "platform": result.get("platform"),
            "dry_run": dry_run,
        })
    save_pending_results(pending, root)
    return pending
