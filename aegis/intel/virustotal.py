"""VirusTotal popular-threat-category client.

``VIRUSTOTAL_API_KEY`` is sent only as the ``x-apikey`` header. A missing key,
an HTTP error, or a body that is not a list of category names never becomes a count.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

CATEGORIES_URL = "https://www.virustotal.com/api/v3/popular_threat_categories"


def api_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "").strip()


def _failure(reason: str) -> Dict[str, Any]:
    return {"ok": False, "reason": reason, "categories": None}


def category_names(data: List[Any]) -> Optional[List[str]]:
    """Unique non-empty names. Returns None when any item is not a string."""
    names: List[str] = []
    seen = set()
    for item in data:
        if not isinstance(item, str):
            return None
        name = item.strip()
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


async def fetch_categories(client: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """GET popular threat categories. ``categories`` is a list only on a real 200 body."""
    key = api_key()
    if not key:
        return _failure("no_key")
    headers = {"x-apikey": key, "Accept": "application/json"}
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=45.0)
    try:
        response = await client.get(CATEGORIES_URL, headers=headers)
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
    if not isinstance(data, list):
        return _failure("unexpected")
    names = category_names(data)
    if names is None:
        return _failure("unexpected")
    return {"ok": True, "reason": "", "categories": names}


def _ensure(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS virustotal_categories (
            name TEXT PRIMARY KEY
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS virustotal_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            synced_at TEXT NOT NULL,
            category_count INTEGER NOT NULL
        )
        """
    )


def clear_snapshot(db) -> None:
    """Drop stored VirusTotal rows. Used by platform reset."""
    with db._get_connection() as conn:
        _ensure(conn)
        conn.execute("DELETE FROM virustotal_categories")
        conn.execute("DELETE FROM virustotal_meta")
        conn.commit()


def snapshot(db) -> Optional[Dict[str, Any]]:
    with db._get_connection() as conn:
        _ensure(conn)
        row = conn.execute(
            "SELECT synced_at, category_count FROM virustotal_meta WHERE id = 1"
        ).fetchone()
    if row is None:
        return None
    return {"synced_at": row["synced_at"], "category_count": row["category_count"]}


def replace_snapshot(db, categories: List[str]) -> int:
    """Replace the stored categories. Refuses an unknown result."""
    if categories is None:
        raise ValueError("refusing to store an unknown VirusTotal result")
    names = category_names(list(categories))
    if names is None:
        raise ValueError("refusing to store VirusTotal items that are not category names")
    synced_at = datetime.now(timezone.utc).isoformat()
    with db._get_connection() as conn:
        _ensure(conn)
        conn.execute("DELETE FROM virustotal_categories")
        conn.executemany(
            "INSERT INTO virustotal_categories (name) VALUES (?)",
            [(name,) for name in names],
        )
        conn.execute(
            """
            INSERT INTO virustotal_meta (id, synced_at, category_count)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                synced_at = excluded.synced_at,
                category_count = excluded.category_count
            """,
            (synced_at, len(names)),
        )
        conn.commit()
    return len(names)
