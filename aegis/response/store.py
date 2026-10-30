"""SQLite for site/asset response policy, audited actions, and agent commands."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.response.policy import RECOMMEND, SITE_DEFAULT_MODE
from aegis.runtime import aegis_data_dir


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResponseStore:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = aegis_data_dir() / "response.sqlite3"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS site_policy (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    site_mode TEXT NOT NULL,
                    auto_allowed INTEGER NOT NULL DEFAULT 0,
                    auto_armed_at TEXT,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS asset_policy (
                    asset_id TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    incident_id TEXT,
                    asset_id TEXT,
                    rule_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS commands (
                    command_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            row = conn.execute("SELECT id FROM site_policy WHERE id = 1").fetchone()
            if not row:
                conn.execute(
                    """
                    INSERT INTO site_policy (id, site_mode, auto_allowed, auto_armed_at, updated_at)
                    VALUES (1, ?, 0, NULL, ?)
                    """,
                    (SITE_DEFAULT_MODE, _now()),
                )

    def site_policy(self) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM site_policy WHERE id = 1").fetchone()
        if not row:
            return {
                "site_mode": SITE_DEFAULT_MODE,
                "auto_allowed": False,
                "auto_armed_at": None,
                "updated_at": None,
            }
        return {
            "site_mode": row["site_mode"] or SITE_DEFAULT_MODE,
            "auto_allowed": bool(row["auto_allowed"]),
            "auto_armed_at": row["auto_armed_at"],
            "updated_at": row["updated_at"],
        }

    def save_site_policy(
        self,
        site_mode: str,
        auto_allowed: bool,
        auto_armed_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = _now()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO site_policy (id, site_mode, auto_allowed, auto_armed_at, updated_at)
                VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    site_mode = excluded.site_mode,
                    auto_allowed = excluded.auto_allowed,
                    auto_armed_at = excluded.auto_armed_at,
                    updated_at = excluded.updated_at
                """,
                (site_mode, 1 if auto_allowed else 0, auto_armed_at, now),
            )
        return self.site_policy()

    def asset_mode(self, asset_id: str) -> str:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT mode FROM asset_policy WHERE asset_id = ?",
                (asset_id,),
            ).fetchone()
        return row["mode"] if row else RECOMMEND

    def set_asset_mode(self, asset_id: str, mode: str) -> Dict[str, Any]:
        now = _now()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO asset_policy (asset_id, mode, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    mode = excluded.mode,
                    updated_at = excluded.updated_at
                """,
                (asset_id, mode, now),
            )
        return {"asset_id": asset_id, "mode": mode, "updated_at": now}

    def list_asset_modes(self) -> Dict[str, str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT asset_id, mode FROM asset_policy").fetchall()
        return {row["asset_id"]: row["mode"] for row in rows}

    def save_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        now = _now()
        action = dict(action)
        action["updated_at"] = now
        action.setdefault("created_at", now)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO actions (
                    action_id, status, incident_id, asset_id, rule_id,
                    created_at, updated_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(action_id) DO UPDATE SET
                    status = excluded.status,
                    incident_id = excluded.incident_id,
                    asset_id = excluded.asset_id,
                    rule_id = excluded.rule_id,
                    updated_at = excluded.updated_at,
                    payload_json = excluded.payload_json
                """,
                (
                    action["action_id"],
                    action.get("status") or "",
                    action.get("incident_id"),
                    action.get("asset_id"),
                    action.get("rule_id"),
                    action.get("created_at") or now,
                    now,
                    json.dumps(action, default=str),
                ),
            )
        return action

    def get_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload_json FROM actions WHERE action_id = ?",
                (action_id,),
            ).fetchone()
        if not row:
            return None
        try:
            data = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def list_actions(
        self,
        incident_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT payload_json FROM actions"
        args: List[Any] = []
        clauses = []
        if incident_id:
            clauses.append("incident_id = ?")
            args.append(incident_id)
        if asset_id:
            clauses.append("asset_id = ?")
            args.append(asset_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        with self._conn() as conn:
            rows = conn.execute(sql, args).fetchall()
        out = []
        for row in rows:
            try:
                data = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                out.append(data)
        return out

    def find_open_action(
        self,
        incident_id: str,
        rule_id: str,
        action: str,
        target: str,
        asset_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        for row in self.list_actions(incident_id=incident_id, asset_id=asset_id, limit=200):
            if row.get("rule_id") != rule_id:
                continue
            if row.get("action") != action or str(row.get("target") or "") != str(target):
                continue
            if row.get("status") in {
                "preview", "queued", "sent", "executed", "applied", "failed", "observed",
            }:
                return row
        return None

    def enqueue_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        now = _now()
        command = dict(command)
        command.setdefault("created_at", now)
        command.setdefault("status", "queued")
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO commands (
                    command_id, agent_id, action_id, status, created_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(command_id) DO UPDATE SET
                    status = excluded.status,
                    payload_json = excluded.payload_json
                """,
                (
                    command["command_id"],
                    command["agent_id"],
                    command["action_id"],
                    command.get("status") or "queued",
                    command.get("created_at") or now,
                    json.dumps(command, default=str),
                ),
            )
        return command

    def pending_commands(self, agent_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT payload_json FROM commands
                WHERE agent_id = ? AND status = 'queued'
                ORDER BY created_at ASC
                """,
                (agent_id,),
            ).fetchall()
        out = []
        for row in rows:
            try:
                data = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict):
                out.append(data)
        return out

    def mark_commands_sent(self, command_ids: List[str]) -> None:
        if not command_ids:
            return
        with self._conn() as conn:
            for cid in command_ids:
                conn.execute(
                    "UPDATE commands SET status = 'sent' WHERE command_id = ? AND status = 'queued'",
                    (cid,),
                )

    def get_command(self, command_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload_json FROM commands WHERE command_id = ?",
                (command_id,),
            ).fetchone()
        if not row:
            return None
        try:
            data = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def save_command(self, command: Dict[str, Any]) -> None:
        self.enqueue_command(command)

    def clear_all(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM asset_policy")
            conn.execute("DELETE FROM actions")
            conn.execute("DELETE FROM commands")
            conn.execute(
                """
                UPDATE site_policy
                SET site_mode = ?, auto_allowed = 0, auto_armed_at = NULL, updated_at = ?
                WHERE id = 1
                """,
                (SITE_DEFAULT_MODE, _now()),
            )


_store: Optional[ResponseStore] = None


def get_response_store() -> ResponseStore:
    global _store
    if _store is None:
        _store = ResponseStore()
    return _store


def reset_response_store(clear: bool = True) -> None:
    global _store
    if _store is not None and clear:
        _store.clear_all()
    _store = None
