"""OTX stores indicators from one subscribed-pulse page, not the subscription total."""

import asyncio

from aegis.database.db import VulnerabilityDatabase
from aegis.database.sync import ThreatFeedSync
from aegis.intel.otx import fetch_subscribed, replace_snapshot


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
    return {item["id"]: item for item in syncer.get_feeds_status()}["alienvault_otx"]


def test_missing_key_does_not_call_or_invent_a_count(tmp_path, monkeypatch):
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    _db, syncer = _syncer(tmp_path)
    client = _Client(_Response(200, {"count": 9000, "results": []}))

    async def run():
        result = await fetch_subscribed(client=client)
        skipped = await syncer.sync_otx()
        return result, skipped

    result, skipped = asyncio.run(run())
    assert result["ok"] is False
    assert result["pulses"] is None
    assert client.calls == []
    assert skipped is None
    feed = _feed(syncer)
    assert feed["status"] == "NOT_WIRED"
    assert feed["has_key"] is False
    assert feed["record_count"] is None


def test_header_and_page_indicators_not_subscription_total(tmp_path, monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    db, syncer = _syncer(tmp_path)
    payload = {
        "count": 9327,
        "results": [
            {
                "id": "pulse-1",
                "indicators": [
                    {"type": "domain", "indicator": "evil.example"},
                    {"type": "domain", "indicator": "evil.example"},
                    {"type": "IPv4", "indicator": "203.0.113.9"},
                    {"type": "", "indicator": "skip.example"},
                ],
            },
            {"id": "pulse-2", "indicators": [{"type": "URL", "indicator": "https://evil.example/a"}]},
        ],
    }
    client = _Client(_Response(200, payload))
    result = asyncio.run(fetch_subscribed(client=client))
    assert result["ok"] is True
    call = client.calls[0]
    assert call["headers"]["X-OTX-API-KEY"] == "test-otx-key"
    assert "test-otx-key" not in call["url"]
    assert call["params"]["limit"] == 10
    assert call["params"]["page"] == 1
    stored = replace_snapshot(db, result["pulses"], result["subscribed_count"])
    assert stored == 3
    feed = _feed(syncer)
    assert feed["status"] == "ACTIVE"
    assert feed["record_count"] == 3
    assert "9327" not in feed["description"]
    assert "first page" in feed["description"]


def test_unexpected_body_is_not_stored(tmp_path, monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "test-otx-key")
    db, syncer = _syncer(tmp_path)
    result = asyncio.run(fetch_subscribed(client=_Client(_Response(200, {"count": 4}))))
    assert result["ok"] is False
    assert result["pulses"] is None

    async def unexpected(client=None):
        return await fetch_subscribed(client=_Client(_Response(200, {"count": 4})))

    monkeypatch.setattr("aegis.intel.otx.fetch_subscribed", unexpected)
    assert asyncio.run(syncer.sync_otx()) is None
    feed = _feed(syncer)
    assert feed["status"] == "CONFIGURED"
    assert feed["record_count"] is None
    with db._get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) FROM otx_meta").fetchone()
    assert row[0] == 0
