"""AbuseIPDB blacklist client.

``ABUSEIPDB_API_KEY`` is sent only as the ``Key`` header. A missing key, an
HTTP error, or a body that is not a list never becomes an address count.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
CONFIDENCE_MINIMUM = 90
LIMIT = 10000


def api_key() -> str:
    return os.getenv("ABUSEIPDB_API_KEY", "").strip()


def _failure(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason, "addresses": None}


async def fetch_blacklist(client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """GET the AbuseIPDB blacklist. ``addresses`` is a list only on a real 200 body."""
    key = api_key()
    if not key:
        return _failure("no_key")
    headers = {"Key": key, "Accept": "application/json"}
    params = {"confidenceMinimum": CONFIDENCE_MINIMUM, "limit": LIMIT}
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=45.0)
    try:
        response = await client.get(BLACKLIST_URL, headers=headers, params=params)
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
    data = payload.get("data")
    if isinstance(data, list):
        return {"ok": True, "reason": "", "addresses": data}
    return _failure("unexpected")


def _ensure(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS abuseipdb_addresses (
            ip TEXT PRIMARY KEY,
            confidence INTEGER,
            country_code TEXT,
            last_reported_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS abuseipdb_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            synced_at TEXT NOT NULL,
            confidence_minimum INTEGER NOT NULL,
            address_count INTEGER NOT NULL
        )
        """
    )


def snapshot(db) -> Optional[Dict[str, Any]]:
    with db._get_connection() as conn:
        _ensure(conn)
        row = conn.execute(
            "SELECT synced_at, confidence_minimum, address_count FROM abuseipdb_meta WHERE id = 1"
        ).fetchone()
    if row is None:
        return None
    return {
        "synced_at": row["synced_at"],
        "confidence_minimum": row["confidence_minimum"],
        "address_count": row["address_count"],
    }


def replace_snapshot(db, addresses: List[Any]) -> int:
    """Replace the stored blacklist. Refuses an unknown result."""
    if addresses is None:
        raise ValueError("refusing to store an unknown AbuseIPDB result")
    rows = []
    seen = set()
    for item in addresses:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ipAddress") or item.get("ip") or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        confidence = item.get("abuseConfidenceScore")
        try:
            confidence_value = int(confidence) if confidence is not None and str(confidence).strip() != "" else None
        except (TypeError, ValueError):
            confidence_value = None
        rows.append(
            (
                ip,
                confidence_value,
                str(item.get("countryCode") or ""),
                str(item.get("lastReportedAt") or ""),
            )
        )
    synced_at = datetime.now(timezone.utc).isoformat()
    with db._get_connection() as conn:
        _ensure(conn)
        conn.execute("DELETE FROM abuseipdb_addresses")
        conn.executemany(
            """
            INSERT INTO abuseipdb_addresses (ip, confidence, country_code, last_reported_at)
            VALUES (?, ?, ?, ?)
            """,
            rows,
        )
        conn.execute(
            """
            INSERT INTO abuseipdb_meta (id, synced_at, confidence_minimum, address_count)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                synced_at = excluded.synced_at,
                confidence_minimum = excluded.confidence_minimum,
                address_count = excluded.address_count
            """,
            (synced_at, CONFIDENCE_MINIMUM, len(rows)),
        )
        conn.commit()
    return len(rows)
