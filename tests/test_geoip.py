"""Local GeoIP lookup: missing file, private addresses, and a reader that returns one point."""

import os
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from fastapi.testclient import TestClient

from aegis.monitor.geoip import GeoIPLookup, public_ip, reload_geoip
from aegis.monitor.network_monitor import NetworkMonitor
from server import app


class _CountingReader:
    def __init__(self, record):
        self.record = record
        self.calls = []

    def city(self, ip):
        self.calls.append(ip)
        if ip != "45.33.32.156":
            raise LookupError(ip)
        return self.record


def _record():
    return SimpleNamespace(
        location=SimpleNamespace(latitude=5.6037, longitude=-0.187),
        city=SimpleNamespace(name="Accra"),
        country=SimpleNamespace(iso_code="GH"),
    )


def test_missing_database_returns_none(tmp_path):
    lookup = GeoIPLookup(path=str(tmp_path / "GeoLite2-City.mmdb"))
    assert lookup.configured is False
    assert lookup.database == "missing"
    assert lookup.lookup("8.8.8.8") is None
    snap = lookup.snapshot(["8.8.8.8", "1.1.1.1"])
    assert snap["configured"] is False
    assert snap["database"] == "missing"
    assert snap["points"] == []


def test_empty_path_returns_none(monkeypatch):
    monkeypatch.delenv("GEOIP_DB_PATH", raising=False)
    lookup = GeoIPLookup(path="")
    assert lookup.lookup("8.8.8.8") is None
    assert lookup.configured is False


def test_mocked_reader_returns_known_coordinate():
    reader = _CountingReader(_record())
    lookup = GeoIPLookup(reader=reader)
    hit = lookup.lookup("45.33.32.156")
    assert hit == {
        "ip": "45.33.32.156",
        "latitude": 5.6037,
        "longitude": -0.187,
        "city": "Accra",
        "country": "GH",
    }
    assert reader.calls == ["45.33.32.156"]


def test_unknown_public_ip_returns_none():
    reader = _CountingReader(_record())
    lookup = GeoIPLookup(reader=reader)
    assert lookup.lookup("1.1.1.1") is None


def test_private_ip_returns_none_without_reading():
    reader = _CountingReader(_record())
    lookup = GeoIPLookup(reader=reader)
    for ip in ("10.1.2.3", "192.168.1.20", "172.16.8.4", "127.0.0.1", "::1"):
        assert lookup.lookup(ip) is None
        assert public_ip(ip) is None
    assert reader.calls == []


def test_zero_zero_is_not_a_coordinate():
    record = _record()
    record.location.latitude = 0.0
    record.location.longitude = 0.0
    lookup = GeoIPLookup(reader=_CountingReader(record))
    assert lookup.lookup("45.33.32.156") is None


def test_monitor_state_uses_lookup_and_skips_private(monkeypatch):
    def fake_snapshot(ips):
        assert "10.0.0.8" in ips
        assert "45.33.32.156" in ips
        return {
            "configured": True,
            "database": "loaded",
            "points": [{
                "ip": "45.33.32.156",
                "latitude": 5.6037,
                "longitude": -0.187,
                "city": "Accra",
                "country": "GH",
            }],
        }

    monkeypatch.setattr("aegis.monitor.network_monitor.geoip_snapshot", fake_snapshot)
    monitor = NetworkMonitor()
    monitor.current_connections = [{
        "local_ip": "10.0.0.8",
        "remote_ip": "45.33.32.156",
        "remote_port": 443,
    }]
    state = monitor.get_state()
    assert state["geoip"]["configured"] is True
    assert state["geoip"]["points"][0]["latitude"] == 5.6037
    assert state["geoip"]["points"][0]["longitude"] == -0.187
    assert all(point["ip"] != "10.0.0.8" for point in state["geoip"]["points"])


def test_fixture_mmdb_returns_known_coordinate(tmp_path):
    """MaxMind's GeoIP2-City-Test.mmdb, fetched into a temp dir and not committed."""
    dest = tmp_path / "GeoIP2-City-Test.mmdb"
    cached = Path("/tmp/GeoIP2-City-Test.mmdb")
    if cached.is_file():
        dest.write_bytes(cached.read_bytes())
    else:
        try:
            urllib.request.urlretrieve(
                "https://github.com/maxmind/MaxMind-DB/raw/main/test-data/GeoIP2-City-Test.mmdb",
                dest,
            )
        except OSError as exc:
            pytest.skip(f"fixture mmdb unavailable: {exc}")
    lookup = GeoIPLookup(path=str(dest))
    assert lookup.configured is True
    hit = lookup.lookup("81.2.69.160")
    assert hit["latitude"] == 51.5142
    assert hit["longitude"] == -0.0931
    assert hit["city"] == "London"
    assert hit["country"] == "GB"
    assert lookup.lookup("10.1.1.1") is None
    assert lookup.lookup("1.1.1.1") is None


def test_settings_field_saves_path_and_missing_file_stays_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("GEOIP_DB_PATH", raising=False)
    missing = tmp_path / "GeoLite2-City.mmdb"
    headers = {"Authorization": f"Bearer {os.environ['AEGIS_ADMIN_TOKEN']}"}
    with TestClient(app) as client:
        saved = client.post(
            "/api/settings",
            headers=headers,
            json={"threat_intel": {"geoip_db_path": str(missing)}},
        )
        assert saved.status_code == 200
        settings = client.get("/api/settings", headers=headers).json()
        assert settings["threat_intel"]["geoip_db_path"] == str(missing)
        state = client.get("/api/monitor", headers=headers).json()
        assert state["geoip"]["configured"] is False
        assert state["geoip"]["database"] == "missing"
        assert state["geoip"]["points"] == []
        cleared = client.post(
            "/api/settings",
            headers=headers,
            json={"threat_intel": {"geoip_db_path": ""}},
        )
        assert cleared.status_code == 200
    assert os.environ.get("GEOIP_DB_PATH", "") == ""
    reload_geoip()
    env_text = open(os.environ["AEGIS_ENV_FILE"], encoding="utf-8").read()
    assert "GEOIP_DB_PATH=" in env_text


def test_map_does_not_invent_coordinates():
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "static" / "index.html").read_text(encoding="utf-8")
    assert "parts[0] * 37" not in html
    assert "GeoIP database is missing" in html
    assert "function resolveHostGeo" in html
    assert "geoip.points" in html or "data.geoip" in html
