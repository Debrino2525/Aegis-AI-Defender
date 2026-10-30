"""ThreatFox stores only indicators returned by the API."""

import asyncio

from aegis.database.db import VulnerabilityDatabase
from aegis.database.sync import ThreatFeedSync
from aegis.intel.threatfox import fetch_iocs, replace_snapshot


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

    async def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "headers": headers, "json": json})
        return self.response


def _syncer(tmp_path):
    db = VulnerabilityDatabase(tmp_path / "vdb.sqlite3")
    return db, ThreatFeedSync(db)


def _feed(syncer, feed_id="threatfox"):
    return {item["id"]: item for item in syncer.get_feeds_status()}[feed_id]


def test_missing_key_does_not_call_or_invent_a_count(tmp_path, monkeypatch):
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    _db, syncer = _syncer(tmp_path)
    client = _Client(_Response(200, {"query_status": "ok", "data": [{"id": "1", "ioc": "1.2.3.4"}]}))

    async def run():
        result = await fetch_iocs(client=client)
        skipped = await syncer.sync_threatfox()
        return result, skipped

    result, skipped = asyncio.run(run())
    assert result["ok"] is False
    assert result["iocs"] is None
    assert client.calls == []
    assert skipped is None
    feed = _feed(syncer)
    assert feed["record_count"] is None
    assert feed["status"] == "NOT_WIRED"
    assert feed["has_key"] is False


def test_auth_key_header_and_real_count(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-auth-key")
    db, syncer = _syncer(tmp_path)
    payload = {
        "query_status": "ok",
        "data": [
            {"id": "10", "ioc": "203.0.113.5:443", "ioc_type": "ip:port", "malware_printable": "Example"},
            {"id": "11", "ioc": "evil.example", "ioc_type": "domain"},
            {"ioc": ""},
        ],
    }
    client = _Client(_Response(200, payload))
    result = asyncio.run(fetch_iocs(days=1, client=client))
    assert result["ok"] is True
    call = client.calls[0]
    assert call["headers"]["Auth-Key"] == "test-auth-key"
    assert "test-auth-key" not in call["url"]
    assert call["json"] == {"query": "get_iocs", "days": 1}
    assert replace_snapshot(db, result["iocs"], result["query_status"], 1) == 2
    feed = _feed(syncer)
    assert feed["status"] == "ACTIVE"
    assert feed["has_key"] is True
    assert feed["record_count"] == 2
    assert "test-auth-key" not in feed["description"]


def test_no_result_stores_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-auth-key")
    db, syncer = _syncer(tmp_path)
    client = _Client(_Response(200, {"query_status": "no_result"}))
    result = asyncio.run(fetch_iocs(client=client))
    assert result["iocs"] == []
    assert replace_snapshot(db, result["iocs"], result["query_status"], 1) == 0
    feed = _feed(syncer)
    assert feed["record_count"] == 0
    assert feed["status"] == "ACTIVE"


def test_http_error_does_not_replace_a_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-auth-key")
    db, syncer = _syncer(tmp_path)
    replace_snapshot(db, [{"id": "9", "ioc": "198.51.100.9"}], "ok", 1)

    async def denied(days=1, client=None):
        return await fetch_iocs(days=days, client=_Client(_Response(403, {"query_status": "unauthorized"})))

    monkeypatch.setattr("aegis.intel.threatfox.fetch_iocs", denied)
    assert asyncio.run(syncer.sync_threatfox()) is None
    feed = _feed(syncer)
    assert feed["record_count"] == 1
    assert "test-auth-key" not in feed["description"]
