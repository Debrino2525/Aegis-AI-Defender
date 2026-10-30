"""Abuse.ch ThreatFox client.

The Auth-Key from ``THREATFOX_AUTH_KEY`` is sent only as the ``Auth-Key``
header. A missing key, an HTTP error, or an unexpected body never becomes
an indicator count.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
MAX_DAYS = 7


def auth_key() -> str:
    return os.getenv("THREATFOX_AUTH_KEY", "").strip()


def _clamp_days(days: int) -> int:
    try:
        value = int(days)
    except (TypeError, ValueError):
        value = 1
    if value < 1:
        return 1
    if value > MAX_DAYS:
        return MAX_DAYS
    return value


def _failure(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason, "query_status": reason, "iocs": None}


async def fetch_iocs(days: int = 1, client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """POST ``get_iocs``. ``iocs`` is a list only when ThreatFox answered ok or no_result."""
    key = auth_key()
    if not key:
        return _failure("no_key")
    body = {"query": "get_iocs", "days": _clamp_days(days)}
    headers = {"Auth-Key": key, "Accept": "application/json"}
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=30.0)
    try:
        response = await client.post(THREATFOX_URL, headers=headers, json=body)
        if response.status_code != 200:
            return _failure(f"http_{response.status_code}")
        try:
            payload = response.json()
        except Exception:
            return _failure("invalid_json")
    except Exception:
        return _failure("unreachable")
    finally:
        if owns_client:
            await client.aclose()

    if not isinstance(payload, dict):
        return _failure("unexpected")
    query_status = str(payload.get("query_status") or "").strip()
    data = payload.get("data")
    if query_status == "no_result":
        return {"ok": True, "reason": "", "query_status": query_status, "iocs": []}
    if query_status == "ok" and isinstance(data, list):
        return {"ok": True, "reason": "", "query_status": query_status, "iocs": data}
    return _failure(query_status or "unexpected")


def _ensure(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threatfox_iocs (
            id TEXT PRIMARY KEY,
            ioc TEXT NOT NULL,
            ioc_type TEXT,
            threat_type TEXT,
            malware TEXT,
            confidence_level INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS threatfox_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            synced_at TEXT NOT NULL,
            query_status TEXT NOT NULL,
            days INTEGER NOT NULL,
            ioc_count INTEGER NOT NULL
        )
        """
    )


def snapshot(db) -> Optional[Dict[str, Any]]:
    """Last successful sync, or None when ThreatFox has never answered."""
    with db._get_connection() as conn:
        _ensure(conn)
        row = conn.execute(
            "SELECT synced_at, query_status, days, ioc_count FROM threatfox_meta WHERE id = 1"
        ).fetchone()
    if row is None:
        return None
    return {
        "synced_at": row["synced_at"],
        "query_status": row["query_status"],
        "days": row["days"],
        "ioc_count": row["ioc_count"],
    }


def replace_snapshot(db, iocs: List[Any], query_status: str, days: int) -> int:
    """Replace the stored snapshot with this response. Refuses an unknown result."""
    if iocs is None:
        raise ValueError("refusing to store an unknown ThreatFox result")
    rows = []
    seen = set()
    for item in iocs:
        if not isinstance(item, dict):
            continue
        ioc = str(item.get("ioc") or "").strip()
        if not ioc:
            continue
        raw_id = str(item.get("id") or ioc).strip()
        if not raw_id or raw_id in seen:
            continue
        seen.add(raw_id)
        confidence = item.get("confidence_level")
        try:
            confidence_value = int(confidence) if confidence is not None and str(confidence).strip() != "" else None
        except (TypeError, ValueError):
            confidence_value = None
        malware = item.get("malware_printable") or item.get("malware") or ""
        rows.append(
            (
                raw_id,
                ioc,
                str(item.get("ioc_type") or ""),
                str(item.get("threat_type") or ""),
                str(malware),
                confidence_value,
            )
        )
    synced_at = datetime.now(timezone.utc).isoformat()
    with db._get_connection() as conn:
        _ensure(conn)
        conn.execute("DELETE FROM threatfox_iocs")
        conn.executemany(
            """
            INSERT INTO threatfox_iocs (id, ioc, ioc_type, threat_type, malware, confidence_level)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.execute(
            """
            INSERT INTO threatfox_meta (id, synced_at, query_status, days, ioc_count)
            VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                synced_at = excluded.synced_at,
                query_status = excluded.query_status,
                days = excluded.days,
                ioc_count = excluded.ioc_count
            """,
            (synced_at, query_status, _clamp_days(days), len(rows)),
        )
        conn.commit()
    return len(rows)
