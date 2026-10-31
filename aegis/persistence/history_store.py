"""
Scan, monitor-alert, and incident-action history under ~/.aegis.

The in-memory dict in server.py is a cache. This store is what survives restart.
"""

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.runtime import aegis_data_dir


_INTERRUPTED = ("queued", "running")


class HistoryStore:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = aegis_data_dir() / "history.sqlite3"
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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    status TEXT,
                    started_at TEXT,
                    updated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS monitor_alerts (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incident_state (
                    source_ip TEXT PRIMARY KEY,
                    incident_id TEXT,
                    status TEXT,
                    actions_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

    def upsert_scan(self, scan: Dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(scan, default=str)
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO scans (id, target, status, started_at, updated_at, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    target = excluded.target,
                    status = excluded.status,
                    started_at = excluded.started_at,
                    updated_at = excluded.updated_at,
                    payload_json = excluded.payload_json
            """, (
                scan["id"],
                scan.get("target", ""),
                scan.get("status", ""),
                scan.get("started_at"),
                now,
                payload,
            ))

    def load_scans(self) -> Dict[str, Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, payload_json FROM scans ORDER BY started_at ASC"
            ).fetchall()
        loaded: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            try:
                scan = json.loads(row["payload_json"])
            except json.JSONDecodeError as exc:
                print(f"[AEGIS] Skipping corrupt scan row {row['id']}: {exc}", file=sys.stderr)
                continue
            if scan.get("status") in _INTERRUPTED:
                scan["status"] = "interrupted"
                scan.setdefault("log", []).append("[!] Scan interrupted by process restart.")
                self.upsert_scan(scan)
            loaded[scan["id"]] = scan
        return loaded

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT payload_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return None

    def delete_scan(self, scan_id: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    def save_monitor_alert(self, alert: Dict[str, Any]) -> None:
        created = alert.get("timestamp") or datetime.now(timezone.utc).isoformat()
        payload = json.dumps(alert, default=str)
        ack = 1 if alert.get("acknowledged") else 0
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO monitor_alerts (id, created_at, acknowledged, payload_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    acknowledged = excluded.acknowledged,
                    payload_json = excluded.payload_json
            """, (alert["id"], created, ack, payload))
            conn.execute("""
                DELETE FROM monitor_alerts WHERE id NOT IN (
                    SELECT id FROM monitor_alerts ORDER BY created_at DESC LIMIT 500
                )
            """)

    def load_monitor_alerts(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM monitor_alerts ORDER BY created_at ASC LIMIT 500"
            ).fetchall()
        alerts: List[Dict[str, Any]] = []
        for row in rows:
            try:
                alerts.append(json.loads(row["payload_json"]))
            except json.JSONDecodeError as exc:
                print(f"[AEGIS] Skipping corrupt monitor alert: {exc}", file=sys.stderr)
        return alerts

    def save_incident_states(self, rows: List[Dict[str, Any]]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute("DELETE FROM incident_state")
            for row in rows:
                source_ip = (row.get("source_ip") or "").strip()
                if not source_ip:
                    continue
                conn.execute("""
                    INSERT INTO incident_state (
                        source_ip, incident_id, status, actions_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    source_ip,
                    row.get("incident_id"),
                    row.get("status") or "ACTIVE",
                    json.dumps(row.get("actions_taken") or []),
                    now,
                ))

    def load_incident_states(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT source_ip, incident_id, status, actions_json FROM incident_state"
            ).fetchall()
        states = []
        for row in rows:
            try:
                actions = json.loads(row["actions_json"] or "[]")
            except json.JSONDecodeError:
                actions = []
            states.append({
                "source_ip": row["source_ip"],
                "incident_id": row["incident_id"],
                "status": row["status"],
                "actions_taken": actions,
            })
        return states

    def clear_operator_history(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM monitor_alerts")
            conn.execute("DELETE FROM incident_state")


_store: Optional[HistoryStore] = None


def get_history_store() -> HistoryStore:
    global _store
    if _store is None:
        _store = HistoryStore()
    return _store
