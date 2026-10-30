"""AbuseIPDB stores only addresses returned by the blacklist API."""

import asyncio

from aegis.database.db import VulnerabilityDatabase
from aegis.database.sync import ThreatFeedSync
from aegis.intel.abuseipdb import fetch_blacklist, replace_snapshot


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
    return {item["id"]: item for item in syncer.get_feeds_status()}["abuseipdb"]


def test_missing_key_does_not_call_or_invent_a_count(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    _db, syncer = _syncer(tmp_path)
    client = _Client(_Response(200, {"data": [{"ipAddress": "203.0.113.5", "abuseConfidenceScore": 100}]}))

    async def run():
        result = await fetch_blacklist(client=client)
        skipped = await syncer.sync_abuseipdb()
        return result, skipped

    result, skipped = asyncio.run(run())
    assert result["ok"] is False
    assert result["addresses"] is None
    assert client.calls == []
    assert skipped is None
    feed = _feed(syncer)
    assert feed["status"] == "NOT_WIRED"
    assert feed["has_key"] is False
    assert feed["record_count"] is None


def test_key_header_and_real_count(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    db, syncer = _syncer(tmp_path)
    payload = {
        "data": [
            {"ipAddress": "203.0.113.5", "abuseConfidenceScore": 100, "countryCode": "ZZ"},
            {"ipAddress": "203.0.113.6", "abuseConfidenceScore": 90},
            {"ipAddress": ""},
            {"ipAddress": "203.0.113.5", "abuseConfidenceScore": 50},
        ]
    }
    client = _Client(_Response(200, payload))
    result = asyncio.run(fetch_blacklist(client=client))
    assert result["ok"] is True
    call = client.calls[0]
    assert call["headers"]["Key"] == "test-abuse-key"
    assert "test-abuse-key" not in call["url"]
    assert call["params"]["confidenceMinimum"] == 90
    assert replace_snapshot(db, result["addresses"]) == 2
    feed = _feed(syncer)
    assert feed["status"] == "ACTIVE"
    assert feed["has_key"] is True
    assert feed["record_count"] == 2
    assert "test-abuse-key" not in feed["description"]


def test_http_error_does_not_replace_a_snapshot(tmp_path, monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    db, syncer = _syncer(tmp_path)
    replace_snapshot(db, [{"ipAddress": "198.51.100.8", "abuseConfidenceScore": 95}])

    async def denied(client=None):
        return await fetch_blacklist(client=_Client(_Response(401, {"errors": [{"detail": "unauthorized"}]})))

    monkeypatch.setattr("aegis.intel.abuseipdb.fetch_blacklist", denied)
    assert asyncio.run(syncer.sync_abuseipdb()) is None
    feed = _feed(syncer)
    assert feed["record_count"] == 1
    assert "test-abuse-key" not in feed["description"]
