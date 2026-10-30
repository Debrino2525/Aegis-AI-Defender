"""Unwired intel must not invent counts, and simulated incidents must not be queued."""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.database.db import VulnerabilityDatabase
from aegis.database.sync import ThreatFeedSync
from server import app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_unwired_feeds_have_no_invented_counts(tmp_path, monkeypatch):
    monkeypatch.delenv("THREATFOX_AUTH_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    db = VulnerabilityDatabase(tmp_path / "vdb.sqlite3")
    feeds = {item["id"]: item for item in ThreatFeedSync(db).get_feeds_status()}
    assert feeds["threatfox"]["status"] == "NOT_WIRED"
    assert feeds["threatfox"]["has_key"] is False
    assert feeds["threatfox"]["record_count"] is None
    assert feeds["abuseipdb"]["status"] == "NOT_WIRED"
    assert feeds["abuseipdb"]["has_key"] is False
    assert feeds["abuseipdb"]["record_count"] is None
    for feed_id in ("alienvault_otx", "virustotal"):
        assert feeds[feed_id]["status"] == "NOT_WIRED"
        assert feeds[feed_id]["record_count"] is None
    rendered = repr(feeds)
    assert "1250" not in rendered


def test_console_does_not_ship_known_fakes():
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    for needle in (
        "10.103.198.26",
        "Accra",
        "1250",
        'value="COM3"',
        "Timeline scrubber",
        "Passive Monitor",
        "All systems operational",
        "[Block IP]",
        "Drop Traffic",
        "Saturday Oct 24",
        "record_count||0",
        "Lookups are not implemented",
        "pre-populated with Darktrace",
        'alt="Globitech Ghana"',
    ):
        assert needle not in html
    assert 'alt="Globitech"' in html
    assert "Not Wired" in html
    sync_src = (ROOT / "aegis" / "database" / "sync.py").read_text(encoding="utf-8")
    assert "1250" not in sync_src
    assert '"record_count": 1250' not in sync_src


def test_intel_tiles_use_real_counts_or_not_wired():
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert "unwired?'Not Wired'" in html.replace(" ", "") or "unwired?'Not Wired'" in html
    assert "f.record_count==null? '0'" in html or "f.record_count==null?'0'" in html
    assert "1250" not in html


def test_reset_clears_stored_intel_counts(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-auth-key")
    db = VulnerabilityDatabase(tmp_path / "vdb.sqlite3")
    from aegis.intel.threatfox import replace_snapshot, snapshot

    replace_snapshot(
        db,
        [{"id": "1", "ioc": "1.2.3.4", "ioc_type": "ip:port"}],
        "ok",
        1,
    )
    assert snapshot(db)["ioc_count"] == 1
    syncer = ThreatFeedSync(db)
    before = {item["id"]: item for item in syncer.get_feeds_status()}
    assert before["threatfox"]["record_count"] == 1
    syncer.clear_api_snapshots()
    assert snapshot(db) is None
    feeds = {item["id"]: item for item in syncer.get_feeds_status()}
    assert feeds["threatfox"]["record_count"] is None
    assert feeds["threatfox"]["status"] == "CONFIGURED"


def test_simulated_alert_is_refused(client):
    headers = {"Authorization": f"Bearer {os.environ['AEGIS_ADMIN_TOKEN']}"}
    denied = client.post("/api/alerting/test", json={"title": "Simulated", "target": "192.168.10.50"})
    assert denied.status_code == 401
    refused = client.post(
        "/api/alerting/test",
        headers=headers,
        json={"title": "Simulated Ransomware Lateral Movement (Test)", "target": "192.168.10.50"},
    )
    assert refused.status_code == 410
    alerts = client.get("/api/alerting/alerts", headers=headers)
    assert alerts.status_code == 200
    titles = [item.get("title", "") for item in alerts.json()]
    assert all("Simulated" not in title for title in titles)
