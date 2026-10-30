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


def test_unwired_feeds_have_no_invented_counts(tmp_path):
    db = VulnerabilityDatabase(tmp_path / "vdb.sqlite3")
    feeds = {item["id"]: item for item in ThreatFeedSync(db).get_feeds_status()}
    for feed_id in ("threatfox", "abuseipdb", "alienvault_otx", "virustotal"):
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
        "Saturday Oct 24",
        "record_count||0",
    ):
        assert needle not in html


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
