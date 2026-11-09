"""AlienVault OTX subscribed-pulse client.

``OTX_API_KEY`` is sent only as the ``X-OTX-API-KEY`` header. A missing key,
an HTTP error, or a body without a pulse list never becomes an indicator count.
The stored count is the number of indicators kept from that page, not the
pulse total OTX reports for the whole subscription.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
PAGE_LIMIT = 10


def api_key() -> str:
    return os.getenv("OTX_API_KEY", "").strip()


def _failure(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason, "pulses": None, "subscribed_count": None}


async def fetch_subscribed(client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """GET one page of subscribed pulses. ``pulses`` is a list only on a real 200 body."""
    key = api_key()
    if not key:
        return _failure("no_key")
    headers = {"X-OTX-API-KEY": key, "Accept": "application/json"}
    params = {"limit": PAGE_LIMIT, "page": 1}
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=45.0)
    try:
        response = await client.get(PULSES_URL, headers=headers, params=params)
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
    results = payload.get("results")
    if not isinstance(results, list):
        return _failure("unexpected")
    subscribed = payload.get("count")
    if not isinstance(subscribed, int):
        subscribed = None
    return {"ok": True, "reason": "", "pulses": results, "subscribed_count": subscribed}


def indicators_from_pulses(pulses: List[Any]) -> Tuple[List[Tuple[str, str, str]], int]:
    """Return unique (indicator, type, pulse id) rows and how many pulse objects were read."""
    rows: List[Tuple[str, str, str]] = []
    seen = set()
    pulse_count = 0
    for pulse in pulses:
        if not isinstance(pulse, dict):
            continue
        pulse_count += 1
        pulse_id = str(pulse.get("id") or "")
        indicators = pulse.get("indicators")
        if not isinstance(indicators, list):
            continue
        for item in indicators:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("type") or "").strip()
            value = str(item.get("indicator") or "").strip()
            if not kind or not value:
                continue
            identity = (kind, value)
            if identity in seen:
                continue
            seen.add(identity)
            rows.append((value, kind, pulse_id))
    return rows, pulse_count


def _ensure(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS otx_indicators (
            indicator TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            pulse_id TEXT,
            PRIMARY KEY (indicator_type, indicator)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS otx_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            synced_at TEXT NOT NULL,
            indicator_count INTEGER NOT NULL,
            pulses_in_page INTEGER NOT NULL,
            page_limit INTEGER NOT NULL,
            subscribed_count INTEGER
        )
        """
    )


def clear_snapshot(db) -> None:
    """Drop stored OTX rows. Used by platform reset."""
    with db._get_connection() as conn:
        _ensure(conn)
        conn.execute("DELETE FROM otx_indicators")
        conn.execute("DELETE FROM otx_meta")
        conn.commit()


def snapshot(db) -> Optional[Dict[str, Any]]:
    with db._get_connection() as conn:
        _ensure(conn)
        row = conn.execute(
            """
            SELECT synced_at, indicator_count, pulses_in_page, page_limit, subscribed_count
            FROM otx_meta WHERE id = 1
            """
        ).fetchone()
    if row is None:
        return None
    return {
        "synced_at": row["synced_at"],
        "indicator_count": row["indicator_count"],
        "pulses_in_page": row["pulses_in_page"],
        "page_limit": row["page_limit"],
        "subscribed_count": row["subscribed_count"],
    }


def replace_snapshot(db, pulses: List[Any], subscribed_count: Optional[int]) -> int:
    """Replace the stored page. Refuses an unknown result."""
    if pulses is None:
        raise ValueError("refusing to store an unknown OTX result")
    rows, pulse_count = indicators_from_pulses(pulses)
    reported = subscribed_count if isinstance(subscribed_count, int) else None
    synced_at = datetime.now(timezone.utc).isoformat()
    with db._get_connection() as conn:
        _ensure(conn)
        conn.execute("DELETE FROM otx_indicators")
        conn.executemany(
            """
            INSERT INTO otx_indicators (indicator, indicator_type, pulse_id)
            VALUES (?, ?, ?)
            """,
            rows,
        )
        conn.execute(
            """
            INSERT INTO otx_meta (
                id, synced_at, indicator_count, pulses_in_page, page_limit, subscribed_count
            )
            VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                synced_at = excluded.synced_at,
                indicator_count = excluded.indicator_count,
                pulses_in_page = excluded.pulses_in_page,
                page_limit = excluded.page_limit,
                subscribed_count = excluded.subscribed_count
            """,
            (synced_at, len(rows), pulse_count, PAGE_LIMIT, reported),
        )
        conn.commit()
    return len(rows)
