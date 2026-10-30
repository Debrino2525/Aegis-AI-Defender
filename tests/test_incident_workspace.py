"""Precision tokens and the Incident Workspace shell."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server import app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_tokens_drop_darktrace_palette():
    tokens = (ROOT / "static" / "design-tokens.css").read_text(encoding="utf-8")
    assert "--dt-magenta" not in tokens
    assert "--dt-purple" not in tokens
    assert "IBM Plex Sans" in tokens
    assert "IBM Plex Mono" in tokens
    assert 'html[data-theme="light"]' in tokens
    assert "#0B0E12" in tokens
    assert "#E8ECF1" in tokens
    assert "#5EEAD4" in tokens
    assert "#E8A23A" in tokens
    assert "#F05260" in tokens
    assert "--radius: 6px" in tokens


def test_shell_links_workspace_and_keeps_unlock(client):
    home = client.get("/")
    assert home.status_code == 200
    text = home.text
    assert "Unlock Aegis" in text
    assert "design-tokens.css" in text
    assert "shell.css" in text
    assert 'href="/incidents"' in text
    assert "--dt-magenta" not in text
    assert "--dt-purple" not in text
    assert "family=Inter" not in text

    page = client.get("/incidents")
    assert page.status_code == 200
    assert "Incident Workspace" in page.text
    assert "Unlock Aegis" in page.text
    assert "/static/incident.js" in page.text

    script = client.get("/static/incident.js")
    assert script.status_code == 200
    body = script.text
    for path in (
        "/api/auth/login",
        "/api/monitor",
        "/api/scans",
        "/api/alerting/alerts",
        "/api/incidents/action",
        "/api/fleet/hosts",
    ):
        assert path in body
    assert "Analyst Assist" in body
    assert "assistBlock" in body
    assert "Observed hops" in body
    assert "world_map.svg" not in body
    assert "Antigena" not in body
    assert "Patterns of Life" not in body

    assert client.get("/api/monitor").status_code == 401
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/alerting/alerts").status_code == 401
