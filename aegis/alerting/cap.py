"""Hourly budget for alerts that leave the console.

Repeats of an open incident stay on that incident. A new incident pages until
the hour's cap is used, then one summary goes out and the rest stay on the
console. The counts live in the alert queue database, so a restart keeps them.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

DEFAULT_HOURLY_CAP = 10
MAX_HOURLY_CAP = 100


def clamp_cap(value: int) -> int:
    return max(1, min(int(value), MAX_HOURLY_CAP))


def hour_key(now: Optional[datetime] = None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H")


def env_hourly_cap() -> int:
    raw = os.getenv("ALERT_HOURLY_CAP", "").strip()
    if raw.isdigit():
        return clamp_cap(int(raw))
    return DEFAULT_HOURLY_CAP


class DispatchCap:
    """Persisted outside-channel budget for one alert queue."""

    def __init__(self, queue, hourly_cap: Optional[int] = None) -> None:
        self.queue = queue
        self._fallback = clamp_cap(hourly_cap) if hourly_cap is not None else None
        self._ensure()

    def _conn(self):
        return self.queue._get_conn()

    def _ensure(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dispatch_hour (
                    hour_key TEXT PRIMARY KEY,
                    sent_count INTEGER NOT NULL DEFAULT 0,
                    held_count INTEGER NOT NULL DEFAULT 0,
                    summary_sent INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dispatch_cap_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    hourly_cap INTEGER NOT NULL
                )
                """
            )

    def _cap_value(self, conn) -> int:
        row = conn.execute(
            "SELECT hourly_cap FROM dispatch_cap_config WHERE id = 1"
        ).fetchone()
        if row is not None:
            return clamp_cap(row["hourly_cap"])
        if self._fallback is not None:
            return self._fallback
        return env_hourly_cap()

    def hourly_cap(self) -> int:
        with self._conn() as conn:
            return self._cap_value(conn)

    def set_hourly_cap(self, value: int) -> int:
        chosen = clamp_cap(value)
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO dispatch_cap_config (id, hourly_cap) VALUES (1, ?)
                ON CONFLICT(id) DO UPDATE SET hourly_cap = excluded.hourly_cap
                """,
                (chosen,),
            )
        return chosen

    def _touch(self, conn, key: str) -> None:
        conn.execute(
            "INSERT OR IGNORE INTO dispatch_hour (hour_key, sent_count, held_count, summary_sent) VALUES (?, 0, 0, 0)",
            (key,),
        )

    def reserve(self, now: Optional[datetime] = None) -> str:
        """Claim a slot. Returns page, summary, or hold."""
        key = hour_key(now)
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._touch(conn, key)
            row = conn.execute(
                "SELECT sent_count, summary_sent FROM dispatch_hour WHERE hour_key = ?",
                (key,),
            ).fetchone()
            cap = self._cap_value(conn)
            if int(row["sent_count"]) < cap:
                conn.execute(
                    "UPDATE dispatch_hour SET sent_count = sent_count + 1 WHERE hour_key = ?",
                    (key,),
                )
                return "page"
            if not int(row["summary_sent"]):
                conn.execute(
                    "UPDATE dispatch_hour SET summary_sent = 1 WHERE hour_key = ?",
                    (key,),
                )
                return "summary"
            return "hold"

    def release_page(self, now: Optional[datetime] = None) -> None:
        key = hour_key(now)
        with self._conn() as conn:
            conn.execute(
                """
                UPDATE dispatch_hour
                SET sent_count = CASE WHEN sent_count > 0 THEN sent_count - 1 ELSE 0 END
                WHERE hour_key = ?
                """,
                (key,),
            )

    def release_summary(self, now: Optional[datetime] = None) -> None:
        key = hour_key(now)
        with self._conn() as conn:
            conn.execute(
                "UPDATE dispatch_hour SET summary_sent = 0 WHERE hour_key = ?",
                (key,),
            )

    def note_held(self, alert_id: str, now: Optional[datetime] = None) -> int:
        """Count one repeat or over-cap alert that stayed on the console."""
        key = hour_key(now)
        held = 0
        with self._conn() as conn:
            self._touch(conn, key)
            conn.execute(
                "UPDATE dispatch_hour SET held_count = held_count + 1 WHERE hour_key = ?",
                (key,),
            )
            if alert_id:
                conn.execute(
                    "UPDATE critical_alerts SET held_count = COALESCE(held_count, 0) + 1 WHERE alert_id = ?",
                    (alert_id,),
                )
                row = conn.execute(
                    "SELECT held_count FROM critical_alerts WHERE alert_id = ?",
                    (alert_id,),
                ).fetchone()
                if row is not None:
                    held = int(row["held_count"])
        return held

    def snapshot(self, now: Optional[datetime] = None) -> dict:
        key = hour_key(now)
        with self._conn() as conn:
            self._touch(conn, key)
            row = conn.execute(
                "SELECT sent_count, held_count, summary_sent FROM dispatch_hour WHERE hour_key = ?",
                (key,),
            ).fetchone()
        return {
            "hourly_cap": self.hourly_cap(),
            "sent_this_hour": int(row["sent_count"]),
            "held_this_hour": int(row["held_count"]),
            "summary_sent": bool(row["summary_sent"]),
            "hour": key,
        }
