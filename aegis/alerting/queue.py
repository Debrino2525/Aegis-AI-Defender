"""
Aegis AI — Persistent SQLite Alert Queue.
Provides reliable, transaction-safe, at-least-once queueing and audit persistence
for critical security alerts across application reboots.
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from aegis.alerting.models import CriticalAlert, DispatchResult, SeverityLevel, DoDZTPillar


class AlertQueue:
    """Persistent SQLite-backed queue for critical alerts and dispatch auditing."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = Path.home() / ".aegis" / "alert_queue.sqlite3"
        else:
            self.db_path = Path(db_path)
            
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS critical_alerts (
                    alert_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    process TEXT,
                    tactic TEXT,
                    technique TEXT,
                    cve_id TEXT,
                    cvss_score REAL,
                    epss_score REAL,
                    is_cisa_kev INTEGER,
                    zt_pillars TEXT,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL, -- PENDING, DISPATCHING, DELIVERED, ACKNOWLEDGED, ESCALATED, FAILED
                    acknowledged INTEGER DEFAULT 0,
                    acknowledged_at TEXT,
                    acknowledged_by TEXT,
                    escalation_level INTEGER DEFAULT 0,
                    occurrence_count INTEGER DEFAULT 1,
                    last_occurrence TEXT NOT NULL,
                    retry_count INTEGER DEFAULT 0,
                    next_retry_at REAL DEFAULT 0,
                    metadata TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON critical_alerts(fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON critical_alerts(status)")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS dispatch_audit (
                    dispatch_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    provider_ref TEXT,
                    error TEXT,
                    latency_ms REAL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (alert_id) REFERENCES critical_alerts(alert_id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS oncall_contacts (
                    contact_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    email TEXT,
                    telegram_chat_id TEXT,
                    whatsapp_number TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS asset_owners (
                    cidr_or_host TEXT PRIMARY KEY,
                    environment TEXT NOT NULL,
                    owner_team TEXT NOT NULL,
                    primary_contact_id TEXT NOT NULL,
                    escalation_contact_id TEXT NOT NULL,
                    escalation_timeout_mins INTEGER DEFAULT 5
                )
            """)

    def enqueue_alert(self, alert: CriticalAlert) -> bool:
        """Enqueues a new critical alert or increments the occurrence count if within flap window."""
        with self._get_conn() as conn:
            pillars_json = json.dumps([p.value if hasattr(p, "value") else str(p) for p in alert.zt_pillars])
            meta_json = json.dumps(alert.metadata)
            
            # Check for existing open/pending alert with identical fingerprint
            existing = conn.execute(
                "SELECT alert_id, occurrence_count FROM critical_alerts WHERE fingerprint = ? AND acknowledged = 0 ORDER BY created_at DESC LIMIT 1",
                (alert.fingerprint,)
            ).fetchone()

            if existing:
                alert.alert_id = existing["alert_id"]
                conn.execute(
                    "UPDATE critical_alerts SET occurrence_count = occurrence_count + 1, last_occurrence = ? WHERE alert_id = ?",
                    (alert.last_occurrence, existing["alert_id"])
                )
                return False  # Deduplicated into existing alert

            conn.execute("""
                INSERT INTO critical_alerts (
                    alert_id, fingerprint, title, severity, summary,
                    source_ip, dest_ip, dest_port, process, tactic,
                    technique, cve_id, cvss_score, epss_score, is_cisa_kev,
                    zt_pillars, created_at, status, acknowledged, acknowledged_at,
                    acknowledged_by, escalation_level, occurrence_count, last_occurrence,
                    retry_count, next_retry_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, NULL, NULL, 0, 1, ?, 0, 0, ?)
            """, (
                alert.alert_id, alert.fingerprint, alert.title, alert.severity.value, alert.summary,
                alert.source_ip, alert.dest_ip, alert.dest_port, alert.process, alert.tactic,
                alert.technique, alert.cve_id, alert.cvss_score, alert.epss_score, 1 if alert.is_cisa_kev else 0,
                pillars_json, alert.created_at, alert.last_occurrence, meta_json
            ))
            return True

    def get_pending_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieves alerts that are ready for dispatch (status PENDING or next_retry_at <= now)."""
        now = time.time()
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT * FROM critical_alerts 
                WHERE (status = 'PENDING' OR (status = 'DISPATCHING' AND next_retry_at <= ?))
                  AND acknowledged = 0
                ORDER BY created_at ASC LIMIT ?
            """, (now, limit)).fetchall()
            return [dict(r) for r in rows]

    def mark_dispatched(self, alert_id: str, new_status: str = "DELIVERED"):
        with self._get_conn() as conn:
            conn.execute("UPDATE critical_alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))

    def record_dispatch_audit(self, alert_id: str, result: DispatchResult):
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO dispatch_audit (
                    alert_id, channel, recipient, success, provider_ref, error, latency_ms, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id, result.channel.value if hasattr(result.channel, "value") else str(result.channel),
                result.recipient, 1 if result.success else 0, result.provider_ref, result.error,
                result.latency_ms, result.timestamp
            ))

    def mark_retry(self, alert_id: str, error: str):
        now = time.time()
        with self._get_conn() as conn:
            row = conn.execute("SELECT retry_count FROM critical_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row:
                retries = row["retry_count"] + 1
                backoff = min(300, 5 * (2 ** retries))  # Exponential backoff capped at 5 mins
                next_retry = now + backoff
                status = "FAILED" if retries >= 5 else "DISPATCHING"
                conn.execute(
                    "UPDATE critical_alerts SET retry_count = ?, next_retry_at = ?, status = ? WHERE alert_id = ?",
                    (retries, next_retry, status, alert_id)
                )

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Marks an alert as acknowledged, stopping all active escalation timers."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            cursor = conn.execute("""
                UPDATE critical_alerts 
                SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ?, status = 'ACKNOWLEDGED'
                WHERE alert_id = ? AND acknowledged = 0
            """, (now_iso, acknowledged_by, alert_id))
            return cursor.rowcount > 0

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM critical_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row:
                d = dict(row)
                d["zt_pillars"] = json.loads(d.get("zt_pillars") or "[]")
                d["metadata"] = json.loads(d.get("metadata") or "{}")
                return d
            return None

    def list_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM critical_alerts ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["zt_pillars"] = json.loads(d.get("zt_pillars") or "[]")
                d["metadata"] = json.loads(d.get("metadata") or "{}")
                results.append(d)
            return results

    def get_unacknowledged_alerts(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM critical_alerts WHERE acknowledged = 0 ORDER BY created_at DESC"
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["zt_pillars"] = json.loads(d.get("zt_pillars") or "[]")
                d["metadata"] = json.loads(d.get("metadata") or "{}")
                results.append(d)
            return results

    # ── On-Call Contacts Persistence ──────────────────────────────────────────
    def list_contacts(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM oncall_contacts ORDER BY name ASC").fetchall()
            return [dict(r) for r in rows]

    def save_contact(self, contact: Dict[str, Any]):
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO oncall_contacts (contact_id, name, role, phone, email, telegram_chat_id, whatsapp_number, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(contact_id) DO UPDATE SET
                    name=excluded.name, role=excluded.role, phone=excluded.phone,
                    email=excluded.email, telegram_chat_id=excluded.telegram_chat_id,
                    whatsapp_number=excluded.whatsapp_number, is_active=excluded.is_active
            """, (
                contact["contact_id"], contact["name"], contact.get("role", "SOC Responder"),
                contact["phone"], contact.get("email"), contact.get("telegram_chat_id"),
                contact.get("whatsapp_number"), 1 if contact.get("is_active", True) else 0
            ))

    def delete_contact(self, contact_id: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM oncall_contacts WHERE contact_id = ?", (contact_id,))
            return cur.rowcount > 0

    # ── Asset Ownership Mappings Persistence ──────────────────────────────────
    def list_mappings(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM asset_owners ORDER BY cidr_or_host ASC").fetchall()
            return [dict(r) for r in rows]

    def save_mapping(self, mapping: Dict[str, Any]):
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO asset_owners (cidr_or_host, environment, owner_team, primary_contact_id, escalation_contact_id, escalation_timeout_mins)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(cidr_or_host) DO UPDATE SET
                    environment=excluded.environment, owner_team=excluded.owner_team,
                    primary_contact_id=excluded.primary_contact_id,
                    escalation_contact_id=excluded.escalation_contact_id,
                    escalation_timeout_mins=excluded.escalation_timeout_mins
            """, (
                mapping["cidr_or_host"], mapping.get("environment", "Production"),
                mapping.get("owner_team", "SOC-Tier2"), mapping["primary_contact_id"],
                mapping["escalation_contact_id"], mapping.get("escalation_timeout_mins", 5)
            ))

    def delete_mapping(self, cidr_or_host: str) -> bool:
        with self._get_conn() as conn:
            cur = conn.execute("DELETE FROM asset_owners WHERE cidr_or_host = ?", (cidr_or_host,))
            return cur.rowcount > 0
