"""VirusTotal stores category names from popular_threat_categories."""

import asyncio

from aegis.database.db import VulnerabilityDatabase
from aegis.database.sync import ThreatFeedSync
from aegis.intel.virustotal import fetch_categories, replace_snapshot


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _Client:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def get(self, url, headers=None, params=None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        return self.response


def _syncer(tmp_path):
    db = VulnerabilityDatabase(tmp_path / "vdb.sqlite3")
    return db, ThreatFeedSync(db)


def _feed(syncer):
    return {item["id"]: item for item in syncer.get_feeds_status()}["virustotal"]


def test_missing_key_does_not_call_or_invent_a_count(tmp_path, monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    _db, syncer = _syncer(tmp_path)
    client = _Client(_Response(200, {"data": ["trojan", "ransomware"]}))

    async def run():
        result = await fetch_categories(client=client)
        skipped = await syncer.sync_virustotal()
        return result, skipped

    result, skipped = asyncio.run(run())
    assert result["ok"] is False
    assert result["categories"] is None
    assert client.calls == []
    assert skipped is None
    feed = _feed(syncer)
    assert feed["status"] == "NOT_WIRED"
    assert feed["has_key"] is False
    assert feed["record_count"] is None


def test_apikey_header_and_category_count(tmp_path, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    db, syncer = _syncer(tmp_path)
    client = _Client(_Response(200, {"data": ["trojan", "trojan", " ransomware ", ""]}))
    result = asyncio.run(fetch_categories(client=client))
    assert result["ok"] is True
    call = client.calls[0]
    assert call["headers"]["x-apikey"] == "test-vt-key"
    assert "test-vt-key" not in call["url"]
    assert replace_snapshot(db, result["categories"]) == 2
    feed = _feed(syncer)
    assert feed["status"] == "ACTIVE"
    assert feed["has_key"] is True
    assert feed["record_count"] == 2


def test_non_string_items_are_not_stored(tmp_path, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    db, syncer = _syncer(tmp_path)
    result = asyncio.run(
        fetch_categories(client=_Client(_Response(200, {"data": [{"id": "trojan"}]})))
    )
    assert result["ok"] is False
    assert result["categories"] is None

    async def unexpected(client=None):
        return await fetch_categories(client=_Client(_Response(200, {"data": [{"id": "trojan"}]})))

    monkeypatch.setattr("aegis.intel.virustotal.fetch_categories", unexpected)
    assert asyncio.run(syncer.sync_virustotal()) is None
    feed = _feed(syncer)
    assert feed["status"] == "CONFIGURED"
    assert feed["record_count"] is None
    with db._get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) FROM virustotal_meta").fetchone()
    assert row[0] == 0
