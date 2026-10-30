"""SQLite for enrollment tokens, enrolled hosts, and heartbeat nonces."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.runtime import aegis_data_dir


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FleetStore:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = aegis_data_dir() / "fleet.sqlite3"
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
                CREATE TABLE IF NOT EXISTS enrollment_tokens (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used_at TEXT,
                    used_by_agent_id TEXT,
                    label TEXT,
                    replaces_agent_id TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS hosts (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    os_name TEXT,
                    os_version TEXT,
                    arch TEXT,
                    agent_version TEXT,
                    cert_fingerprint TEXT NOT NULL,
                    cert_pem TEXT NOT NULL,
                    enrolled_at TEXT NOT NULL,
                    last_seen TEXT,
                    last_telemetry_json TEXT,
                    remote_ip TEXT,
                    revoked_at TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS heartbeat_nonces (
                    nonce TEXT PRIMARY KEY,
                    seen_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS revoked_certs (
                    fingerprint TEXT PRIMARY KEY,
                    agent_id TEXT,
                    revoked_at TEXT NOT NULL,
                    reason TEXT
                )
                """
            )
            self._ensure_column(conn, "enrollment_tokens", "replaces_agent_id", "TEXT")
            self._ensure_column(conn, "hosts", "revoked_at", "TEXT")

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        names = {str(r[1]) for r in rows}
        if column not in names:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def insert_token(
        self,
        token_id: str,
        token_hash: str,
        expires_at: str,
        label: str = "",
        replaces_agent_id: Optional[str] = None,
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO enrollment_tokens
                    (id, token_hash, created_at, expires_at, label, replaces_agent_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_id, token_hash, _now(), expires_at, label, replaces_agent_id),
            )

    def unused_token_count(self) -> int:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS n FROM enrollment_tokens
                WHERE used_at IS NULL AND expires_at > ?
                """,
                (_now(),),
            ).fetchone()
        return int(row["n"] if row else 0)

    def lookup_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM enrollment_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        return dict(row) if row else None

    def consume_token(self, token_id: str, agent_id: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                """
                UPDATE enrollment_tokens
                SET used_at = ?, used_by_agent_id = ?
                WHERE id = ? AND used_at IS NULL AND expires_at > ?
                """,
                (_now(), agent_id, token_id, _now()),
            )
            return cur.rowcount == 1

    def upsert_host(self, row: Dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO hosts (
                    agent_id, hostname, os_name, os_version, arch, agent_version,
                    cert_fingerprint, cert_pem, enrolled_at, last_seen,
                    last_telemetry_json, remote_ip, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    hostname = excluded.hostname,
                    os_name = excluded.os_name,
                    os_version = excluded.os_version,
                    arch = excluded.arch,
                    agent_version = excluded.agent_version,
                    cert_fingerprint = excluded.cert_fingerprint,
                    cert_pem = excluded.cert_pem,
                    last_seen = excluded.last_seen,
                    last_telemetry_json = excluded.last_telemetry_json,
                    remote_ip = excluded.remote_ip
                """,
                (
                    row["agent_id"],
                    row.get("hostname") or "",
                    row.get("os_name") or "",
                    row.get("os_version") or "",
                    row.get("arch") or "",
                    row.get("agent_version") or "",
                    row["cert_fingerprint"],
                    row["cert_pem"],
                    row.get("enrolled_at") or _now(),
                    row.get("last_seen"),
                    row.get("last_telemetry_json"),
                    row.get("remote_ip"),
                    row.get("revoked_at"),
                ),
            )

    def mark_host_revoked(self, agent_id: str, revoked_at: str) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE hosts SET revoked_at = ? WHERE agent_id = ?",
                (revoked_at, agent_id),
            )
            return cur.rowcount == 1

    def clear_host_revocation(self, agent_id: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE hosts SET revoked_at = NULL WHERE agent_id = ?",
                (agent_id,),
            )

    def revoke_fingerprint(self, fingerprint: str, agent_id: str, reason: str = "operator") -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO revoked_certs (fingerprint, agent_id, revoked_at, reason)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    agent_id = excluded.agent_id,
                    revoked_at = excluded.revoked_at,
                    reason = excluded.reason
                """,
                (fingerprint, agent_id, _now(), reason),
            )

    def is_revoked_fingerprint(self, fingerprint: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM revoked_certs WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        return row is not None

    def get_host(self, agent_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hosts WHERE agent_id = ?", (agent_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_host_by_fingerprint(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM hosts WHERE cert_fingerprint = ?", (fingerprint,)
            ).fetchone()
        return dict(row) if row else None

    def list_heartbeated_hosts(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM hosts
                WHERE last_seen IS NOT NULL AND last_seen != ''
                ORDER BY last_seen DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def list_all_hosts(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM hosts
                ORDER BY (last_seen IS NULL OR last_seen = ''), last_seen DESC, enrolled_at DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def enrolled_count(self) -> int:
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM hosts").fetchone()
        return int(row["n"] if row else 0)

    def heartbeated_count(self) -> int:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS n FROM hosts
                WHERE last_seen IS NOT NULL AND last_seen != ''
                """
            ).fetchone()
        return int(row["n"] if row else 0)

    def revoked_count(self) -> int:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS n FROM hosts
                WHERE revoked_at IS NOT NULL AND revoked_at != ''
                """
            ).fetchone()
        return int(row["n"] if row else 0)

    def remember_nonce(self, nonce: str) -> bool:
        """Return True if the nonce is new. False on replay."""
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO heartbeat_nonces (nonce, seen_at) VALUES (?, ?)",
                    (nonce, _now()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def prune_nonces(self, older_than_iso: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM heartbeat_nonces WHERE seen_at < ?",
                (older_than_iso,),
            )

    def clear_all(self) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM enrollment_tokens")
            conn.execute("DELETE FROM hosts")
            conn.execute("DELETE FROM heartbeat_nonces")
            conn.execute("DELETE FROM revoked_certs")


_store: Optional[FleetStore] = None


def get_fleet_store() -> FleetStore:
    global _store
    if _store is None:
        _store = FleetStore()
    return _store


def reset_fleet_store(clear: bool = True) -> None:
    global _store
    if _store is not None and clear:
        _store.clear_all()
    _store = None
