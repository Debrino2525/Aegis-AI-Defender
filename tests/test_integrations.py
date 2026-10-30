"""Slack, Teams, and email Connect. Secrets never leave the status payload."""

import asyncio
import json
from pathlib import Path

from aegis.alerting.integrations import (
    PlatformConnections,
    app_credentials,
    authorize_url,
    connect_start,
    slack_connection,
)
from aegis.alerting.models import (
    AssetOwnerMapping,
    ChannelType,
    DispatchResult,
    OnCallContact,
)
from aegis.alerting.queue import AlertQueue
from aegis.alerting.router import AlertRouter

ROOT = Path(__file__).resolve().parents[1]


def test_slack_connection_rejects_unusable_payloads():
    assert slack_connection({
        "ok": False,
        "incoming_webhook": {"url": "https://hooks.slack.com/services/T/B/x"},
    }) is None
    assert slack_connection({
        "ok": True,
        "incoming_webhook": {"url": "http://hooks.slack.com/services/T/B/x"},
    }) is None
    assert slack_connection({"ok": True}) is None
    good = slack_connection({
        "ok": True,
        "team": {"name": "Acme"},
        "incoming_webhook": {
            "url": "https://hooks.slack.com/services/T/B/secret",
            "channel": "#soc",
        },
    })
    assert good["account_label"] == "Acme"
    assert good["destination_label"] == "#soc"
    assert good["secret"].startswith("https://")


def test_public_status_omits_secrets(tmp_path):
    queue = AlertQueue(tmp_path / "alerts.sqlite3")
    platforms = PlatformConnections(queue)
    platforms.save("slack", "", {
        "account_label": "Acme",
        "destination_label": "#soc",
        "secret": "https://hooks.slack.com/services/T/B/super-secret-hook",
        "secret_kind": "webhook",
    })
    platforms.save("teams", "ONCALL-ABC123", {
        "account_label": "Ada",
        "destination_label": "team-id/channel-id",
        "secret": "ya29.super-secret-token",
        "refresh_token": "refresh-secret",
        "secret_kind": "bearer",
    })
    rendered = json.dumps(platforms.public())
    assert "super-secret-hook" not in rendered
    assert "ya29.super-secret-token" not in rendered
    assert "refresh-secret" not in rendered
    assert "team-id/channel-id" not in rendered
    assert "Ada" in rendered
    assert "#soc" in rendered
    assert platforms.destination_for("ONCALL-ABC123")["provider"] == "teams"
    assert platforms.destination_for("someone-else")["provider"] == "slack"
    state = platforms.begin("slack", "")
    assert platforms.take_state(state)["provider"] == "slack"
    assert platforms.take_state(state) is None


def test_connect_without_app_asks_for_setup(monkeypatch):
    monkeypatch.delenv("SLACK_CLIENT_ID", raising=False)
    monkeypatch.delenv("SLACK_CLIENT_SECRET", raising=False)
    assert app_credentials("slack") is None
    payload = connect_start("slack", "http://127.0.0.1:8000")
    assert payload["setup_required"] is True
    assert payload["redirect_uri"] == "http://127.0.0.1:8000/api/integrations/slack/callback"
    assert "secret" not in payload
    monkeypatch.setenv("SLACK_CLIENT_ID", "111.222")
    monkeypatch.setenv("SLACK_CLIENT_SECRET", "super-secret-value")
    url = authorize_url("slack", "http://127.0.0.1:8000", "state-token")
    assert url.startswith("https://slack.com/oauth/v2/authorize?")
    assert "super-secret-value" not in url
    assert "state-token" in url
    assert connect_start("slack", "http://127.0.0.1:8000") == {"ready": True}


def test_connected_platform_is_paged_and_sms_is_not(tmp_path, monkeypatch):
    queue = AlertQueue(tmp_path / "alerts.sqlite3")
    router = AlertRouter(queue=queue)
    router.platforms.save("slack", "", {
        "account_label": "Acme",
        "destination_label": "#soc",
        "secret": "https://hooks.slack.com/services/T/B/super-secret-hook",
        "secret_kind": "webhook",
    })
    called = []

    async def fake_deliver(connection, text, client=None):
        called.append(connection["provider"])
        assert "super-secret-hook" not in text
        return DispatchResult(channel=ChannelType.WEBHOOK, success=True, recipient="#soc")

    monkeypatch.setattr("aegis.alerting.router.deliver", fake_deliver)

    class _Boom:
        telegram_bot_token = ""
        telegram_chat_id = ""
        whatsapp_token = ""
        whatsapp_phone_id = ""
        generic_webhook_url = "https://example.test/hook"
        arkesel_api_key = "sms-key"
        hubtel_client_id = ""
        port = "COM9"

        async def send(self, *args, **kwargs):
            raise AssertionError("fallback channel was used")

    router.adapter_webhook = _Boom()
    router.adapter_sms = _Boom()
    router.adapter_modem = _Boom()
    router.escalation.add_contact(OnCallContact(contact_id="ops", name="Ops", phone="+15555550100"))
    router.escalation.add_owner_mapping(AssetOwnerMapping(
        cidr_or_host="10.8.0.0/16",
        environment="Lab",
        owner_team="SOC",
        primary_contact_id="ops",
        escalation_contact_id="ops",
    ))

    async def run():
        routed = await router.route_behavioral_alert({
            "pattern_id": "AEGIS-BEH-002",
            "title": "C2 Beaconing Pattern",
            "severity": "CRITICAL",
            "source_ip": "10.8.0.9",
            "dest_ip": "203.0.113.10",
            "dest_port": 4444,
            "tactic": "Command and Control",
        })
        assert routed is not None

    asyncio.run(run())
    assert called == ["slack"]
    rendered = json.dumps(router.get_status())
    assert "super-secret-hook" not in rendered
    assert "Acme" in rendered


def test_console_leads_with_connect_not_sms():
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert "Slack, Microsoft Teams, or email" in html
    assert 'id="platform-setup"' in html
    assert "function connectPlatform" in html
    for gone in (
        "Other channels",
        "SMS gateway",
        "Telegram",
        "WhatsApp",
        "ChatOps",
        "Cellular",
        "Canary",
        "cfg-arkesel-key",
        "cfg-canary-url",
    ):
        assert gone not in html
    assert 'id="alert-channels-grid"' in html
    cards = html[html.index("function platformCardsHtml"):html.index("function paintPlatformCards")]
    assert "Slack" in cards
    assert "Microsoft Teams" in cards
    assert "Connect Microsoft" in cards
    assert ">SMS<" not in cards
