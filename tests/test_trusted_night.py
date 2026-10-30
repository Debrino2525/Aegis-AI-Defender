"""Auth denial, secret masking, and scan history across a simulated restart."""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis.alerting.security import (
    PUBLIC_DEFAULT_SIGNING_KEY,
    generate_triage_token,
    resolve_signing_key,
    signing_key_text,
)
from aegis.monitor.ai_analyst import AIAnalyst
from aegis.persistence.history_store import HistoryStore, get_history_store
from aegis.runtime import all_interfaces_warning, listen_host
from aegis.security.console_auth import ConsoleAuth
from server import app, remember_scan, restore_history, scans


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def _auth_header():
    return {"Authorization": f"Bearer {os.environ['AEGIS_ADMIN_TOKEN']}"}


def test_api_and_containment_require_auth(client):
    assert client.get("/").status_code == 200
    assert "Unlock Aegis" in client.get("/").text

    status = client.get("/api/auth/status")
    assert status.status_code == 200
    assert status.json()["authenticated"] is False

    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/settings").status_code == 401
    assert client.get("/api/response/policy").status_code == 401
    assert client.get("/api/response/actions").status_code == 401
    denied = client.post(
        "/api/incidents/action",
        json={"incident_id": "INC-1", "action_type": "terminate_process", "target": "evil.exe"},
    )
    assert denied.status_code == 401

    token = os.environ["AEGIS_ADMIN_TOKEN"]
    assert client.get(f"/api/scans?token={token}").status_code == 401
    assert client.get("/api/scans", headers={"Authorization": "Bearer wrong-token"}).status_code == 401

    allowed = client.get("/api/scans", headers=_auth_header())
    assert allowed.status_code == 200

    missing = client.post(
        "/api/incidents/action",
        headers=_auth_header(),
        json={"incident_id": "INC-DOES-NOT-EXIST", "action_type": "terminate_process", "target": "evil.exe"},
    )
    assert missing.status_code == 404

    # HMAC triage is its own credential. A bad token is rejected without an admin session.
    triage = client.get("/api/alerting/triage/not-a-real-token")
    assert triage.status_code == 403


def test_session_cookie_login_and_logout(client):
    bad = client.post("/api/auth/login", json={"secret": "not-the-admin-token"})
    assert bad.status_code == 401
    assert client.get("/api/scans").status_code == 401

    ok = client.post("/api/auth/login", json={"password": os.environ["AEGIS_ADMIN_TOKEN"]})
    assert ok.status_code == 200
    assert ok.json()["authenticated"] is True
    assert "aegis_session" in client.cookies

    assert client.get("/api/auth/status").json()["authenticated"] is True
    assert client.get("/api/scans").status_code == 200

    logged_out = client.post("/api/auth/logout")
    assert logged_out.status_code == 200
    assert client.get("/api/scans").status_code == 401


def test_websockets_require_auth(client):
    token = os.environ["AEGIS_ADMIN_TOKEN"]
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/monitor") as ws:
            ws.receive_json()

    with client.websocket_connect(f"/ws/monitor?token={token}") as ws:
        payload = ws.receive_json()
        assert "alerts" in payload

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/scan/MISSING") as ws:
            ws.receive_json()


def test_settings_mask_secrets_and_ignore_masked_echo(client, monkeypatch):
    secret = "nvd-live-secret-value-zzzz"
    webhook = "https://hooks.example.com/services/SUPERSECRETTOKEN"
    telegram = "123456:telegram-bot-token-secret"
    monkeypatch.setenv("NVD_API_KEY", secret)
    monkeypatch.setenv("CRITICAL_ALERT_WEBHOOK_URL", webhook)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", telegram)
    monkeypatch.setenv("HUBTEL_CLIENT_SECRET", "hubtel-client-secret-value")

    assert client.get("/api/settings").status_code == 401
    res = client.get("/api/settings", headers=_auth_header())
    assert res.status_code == 200
    body = res.text
    assert secret not in body
    assert "SUPERSECRETTOKEN" not in body
    assert "telegram-bot-token-secret" not in body
    assert "hubtel-client-secret-value" not in body
    assert signing_key_text() not in body
    assert os.environ["AEGIS_ADMIN_TOKEN"] not in body
    assert PUBLIC_DEFAULT_SIGNING_KEY not in body

    data = res.json()
    assert data["threat_intel"]["has_nvd"] is True
    assert data["threat_intel"]["nvd_api_key"] != secret
    assert "..." in data["threat_intel"]["nvd_api_key"]
    assert data["alerting"]["critical_alert_webhook_url"] == "https://hooks.example.com/***"
    assert data["alerting"]["alert_signing_key"]
    assert data["alerting"]["alert_signing_key_rejected_default"] is False

    echo = client.post(
        "/api/settings",
        headers=_auth_header(),
        json={
            "threat_intel": {"nvd_api_key": data["threat_intel"]["nvd_api_key"]},
            "alerting": {
                "critical_alert_webhook_url": data["alerting"]["critical_alert_webhook_url"],
                "telegram_bot_token": data["alerting"]["telegram_bot_token"],
                "alert_signing_key": data["alerting"]["alert_signing_key"],
            },
        },
    )
    assert echo.status_code == 200
    assert os.environ["NVD_API_KEY"] == secret
    assert os.environ["CRITICAL_ALERT_WEBHOOK_URL"] == webhook
    assert os.environ["TELEGRAM_BOT_TOKEN"] == telegram
    env_text = Path(os.environ["AEGIS_ENV_FILE"]).read_text(encoding="utf-8")
    assert secret not in env_text
    assert "SUPERSECRETTOKEN" not in env_text
    assert signing_key_text() not in env_text


def test_scan_persists_across_simulated_restart(client):
    sid = "SCANRESTART1"
    remember_scan({
        "id": sid,
        "target": "127.0.0.1",
        "status": "done",
        "started_at": "2026-10-30T00:00:00",
        "duration": 1.2,
        "total_findings": 2,
        "severity_breakdown": {"HIGH": 2},
        "findings": [{"id": "F1", "title": "Example"}],
        "log": ["complete"],
        "services": [],
        "open_ports": [80],
    })
    listed = client.get("/api/scans", headers=_auth_header())
    assert listed.status_code == 200
    assert any(row["id"] == sid for row in listed.json())

    scans.clear()
    assert sid not in scans
    fresh = HistoryStore(get_history_store().db_path)
    restored = fresh.get_scan(sid)
    assert restored["target"] == "127.0.0.1"
    assert restored["findings"][0]["id"] == "F1"

    restore_history()
    again = client.get(f"/api/scans/{sid}", headers=_auth_header())
    assert again.status_code == 200
    assert again.json()["target"] == "127.0.0.1"
    assert again.json()["total_findings"] == 2
    assert client.get(f"/api/scans/{sid}").status_code == 401


def test_running_scan_and_incident_state_survive_new_store(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    store.upsert_scan({
        "id": "RUN1",
        "target": "10.0.0.5",
        "status": "running",
        "started_at": "2026-10-30T00:00:00",
        "log": [],
    })
    loaded = store.load_scans()
    assert loaded["RUN1"]["status"] == "interrupted"
    assert any("interrupted" in line.lower() for line in loaded["RUN1"]["log"])

    alert = {
        "id": "ALT-0007",
        "title": "Beacon",
        "severity": "HIGH",
        "acknowledged": False,
        "timestamp": "2026-10-30T00:00:01",
        "_timestamp": 10.0,
        "_dedup_key": "AEGIS-BEH-002:10.1.1.1:1.2.3.4",
        "source_ip": "10.1.1.1",
    }
    store.save_monitor_alert(alert)
    store.save_incident_states([{
        "source_ip": "10.1.1.1",
        "incident_id": "INC-0001",
        "status": "CONTAINED",
        "actions_taken": [{"action": "block_ip", "success": True}],
    }])

    other = HistoryStore(tmp_path / "history.sqlite3")
    alerts = other.load_monitor_alerts()
    assert alerts[0]["id"] == "ALT-0007"
    assert alerts[0]["_dedup_key"].startswith("AEGIS-BEH-002")
    rows = other.load_incident_states()
    assert rows[0]["status"] == "CONTAINED"

    analyst = AIAnalyst()
    analyst.restore_operator_state(rows)
    incidents = analyst.analyze([{
        "id": "ALT-0007",
        "source_ip": "10.1.1.1",
        "dest_ip": "1.2.3.4",
        "severity": "HIGH",
        "tactic": "Command and Control",
        "pattern_id": "AEGIS-BEH-002",
        "_timestamp": 10.0,
    }])
    assert incidents[0]["status"] == "CONTAINED"
    assert incidents[0]["actions_taken"][0]["action"] == "block_ip"


def test_public_default_signing_key_is_rejected(tmp_path, monkeypatch):
    key, source, warning = resolve_signing_key(
        env_value=PUBLIC_DEFAULT_SIGNING_KEY,
        data_dir=tmp_path,
        dev=False,
        allow_insecure=True,
    )
    assert source == "generated"
    assert key.decode("utf-8") != PUBLIC_DEFAULT_SIGNING_KEY
    assert warning and "WARNING" in warning and "REJECTED" in warning
    assert (tmp_path / "alert_signing_key").read_text(encoding="utf-8").strip() == key.decode("utf-8")
    assert (tmp_path / "alert_signing_key").stat().st_mode & 0o777 == 0o600

    again, source2, _ = resolve_signing_key(
        env_value="",
        data_dir=tmp_path,
        dev=False,
    )
    assert source2 == "persisted"
    assert again == key

    real, source3, warning3 = resolve_signing_key(
        env_value="unique-operator-key-0123456789",
        data_dir=tmp_path / "other",
        dev=False,
    )
    assert source3 == "env"
    assert warning3 is None
    assert real.decode("utf-8") == "unique-operator-key-0123456789"

    import aegis.alerting.security as sec
    monkeypatch.setattr(sec, "SIGNING_KEY", PUBLIC_DEFAULT_SIGNING_KEY.encode("utf-8"))
    monkeypatch.setenv("AEGIS_DEV", "0")
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.delenv("AEGIS_ALLOW_INSECURE_SIGNING_KEY", raising=False)
    with pytest.raises(RuntimeError):
        generate_triage_token("CALT-1", "ONCALL-1")


def test_admin_token_generated_outside_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("AEGIS_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_ADMIN_PASSWORD", raising=False)
    auth = ConsoleAuth()
    auth.bootstrap()
    assert auth.generated is True
    token_path = tmp_path / "admin_token"
    assert token_path.read_text(encoding="utf-8").strip() == auth.token
    assert auth.token not in ("", "admin", "password", "aegis")
    assert token_path.stat().st_mode & 0o777 == 0o600

    again = ConsoleAuth()
    again.bootstrap()
    assert again.generated is False
    assert again.token == auth.token
    assert again.check_secret(auth.token) is True
    assert again.check_secret("wrong-password") is False


def test_default_bind_is_loopback(monkeypatch):
    monkeypatch.delenv("AEGIS_HOST", raising=False)
    assert listen_host() == "127.0.0.1"
    assert all_interfaces_warning("127.0.0.1") is None
    warning = all_interfaces_warning("0.0.0.0")
    assert warning and "WARNING" in warning
