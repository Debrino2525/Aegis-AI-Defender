"""Connect Slack, Microsoft Teams, and email.

A responder taps Connect. If this console already has the provider app
credentials, the browser goes to that provider's sign-in. The access secret
stays in the local alert queue and is never returned by the status API.
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx

from aegis.alerting.models import ChannelType, DispatchResult

PROVIDERS = ("slack", "teams", "email_microsoft", "email_google")

_APP = {
    "slack": ("SLACK_CLIENT_ID", "SLACK_CLIENT_SECRET"),
    "teams": ("MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"),
    "email_microsoft": ("MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"),
    "email_google": ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"),
}

_SCOPES = {
    "slack": "incoming-webhook",
    "teams": "offline_access User.Read ChannelMessage.Send",
    "email_microsoft": "offline_access User.Read Mail.Send",
    "email_google": "openid email https://www.googleapis.com/auth/gmail.send",
}


def credential_env_names(provider: str) -> tuple:
    if provider not in _APP:
        raise ValueError("unknown provider")
    return _APP[provider]


def app_credentials(provider: str) -> Optional[tuple]:
    client_id_name, secret_name = credential_env_names(provider)
    client_id = os.getenv(client_id_name, "").strip()
    secret = os.getenv(secret_name, "").strip()
    if not client_id or not secret:
        return None
    return client_id, secret


def connect_start(provider: str, base_url: str) -> Dict[str, Any]:
    """What Connect should do before a browser leaves the console.

    Without an app registration this stays on the console and asks for the
    client id and secret. It never claims the account is connected.
    """
    if provider not in PROVIDERS:
        raise ValueError("unknown provider")
    if app_credentials(provider) is None:
        return {
            "setup_required": True,
            "provider": provider,
            "redirect_uri": redirect_uri(base_url, provider),
        }
    return {"ready": True}


def redirect_uri(base_url: str, provider: str) -> str:
    return base_url.rstrip("/") + "/api/integrations/" + provider + "/callback"


def authorize_url(provider: str, base_url: str, state: str) -> str:
    creds = app_credentials(provider)
    if creds is None:
        raise RuntimeError("missing_app")
    client_id, _secret = creds
    redirect = redirect_uri(base_url, provider)
    if provider == "slack":
        query = urlencode({
            "client_id": client_id,
            "scope": _SCOPES["slack"],
            "redirect_uri": redirect,
            "state": state,
        })
        return "https://slack.com/oauth/v2/authorize?" + query
    if provider in ("teams", "email_microsoft"):
        query = urlencode({
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect,
            "response_mode": "query",
            "scope": _SCOPES[provider],
            "state": state,
        })
        return "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + query
    query = urlencode({
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect,
        "scope": _SCOPES["email_google"],
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    })
    return "https://accounts.google.com/o/oauth2/v2/auth?" + query


def slack_connection(payload: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Pull the webhook Slack returns. Nothing else is stored."""
    if not isinstance(payload, dict) or not payload.get("ok"):
        return None
    hook = payload.get("incoming_webhook") or {}
    url = str(hook.get("url") or "").strip()
    if not url.startswith("https://"):
        return None
    team = str((payload.get("team") or {}).get("name") or "Slack")
    channel = str(hook.get("channel") or "")
    return {
        "account_label": team,
        "destination_label": channel,
        "secret": url,
        "secret_kind": "webhook",
    }


def bearer_connection(account_label: str, destination_label: str, access_token: str, refresh_token: str = "") -> Optional[Dict[str, str]]:
    token = (access_token or "").strip()
    if not token:
        return None
    return {
        "account_label": account_label.strip() or "Connected account",
        "destination_label": destination_label.strip(),
        "secret": token,
        "secret_kind": "bearer",
        "refresh_token": (refresh_token or "").strip(),
    }


class PlatformConnections:
    """Local record of connected Slack, Teams, and mail accounts."""

    def __init__(self, queue) -> None:
        self.queue = queue
        self._ensure()

    def _conn(self):
        return self.queue._get_conn()

    def _ensure(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS platform_connections (
                    provider TEXT NOT NULL,
                    contact_id TEXT NOT NULL DEFAULT '',
                    account_label TEXT NOT NULL,
                    destination_label TEXT NOT NULL DEFAULT '',
                    secret TEXT NOT NULL,
                    refresh_token TEXT NOT NULL DEFAULT '',
                    secret_kind TEXT NOT NULL,
                    connected_at TEXT NOT NULL,
                    PRIMARY KEY (provider, contact_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS oauth_states (
                    state TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    contact_id TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                )
                """
            )

    def begin(self, provider: str, contact_id: str = "") -> str:
        if provider not in PROVIDERS:
            raise ValueError("unknown provider")
        state = secrets.token_urlsafe(24)
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO oauth_states (state, provider, contact_id, created_at) VALUES (?, ?, ?, ?)",
                (state, provider, contact_id or "", datetime.now(timezone.utc).isoformat()),
            )
        return state

    def take_state(self, state: str) -> Optional[Dict[str, str]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT provider, contact_id, created_at FROM oauth_states WHERE state = ?",
                (state,),
            ).fetchone()
            if row is None:
                return None
            conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
        return {"provider": row["provider"], "contact_id": row["contact_id"]}

    def save(self, provider: str, contact_id: str, fields: Dict[str, str]) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO platform_connections (
                    provider, contact_id, account_label, destination_label,
                    secret, refresh_token, secret_kind, connected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, contact_id) DO UPDATE SET
                    account_label = excluded.account_label,
                    destination_label = excluded.destination_label,
                    secret = excluded.secret,
                    refresh_token = excluded.refresh_token,
                    secret_kind = excluded.secret_kind,
                    connected_at = excluded.connected_at
                """,
                (
                    provider,
                    contact_id or "",
                    fields["account_label"],
                    fields.get("destination_label") or "",
                    fields["secret"],
                    fields.get("refresh_token") or "",
                    fields["secret_kind"],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def disconnect(self, provider: str, contact_id: str = "") -> None:
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM platform_connections WHERE provider = ? AND contact_id = ?",
                (provider, contact_id or ""),
            )

    def public(self) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT provider, contact_id, account_label, destination_label, connected_at
                FROM platform_connections ORDER BY provider, account_label
                """
            ).fetchall()
        visible = []
        for row in rows:
            destination = row["destination_label"] or ""
            if "/" in destination:
                destination = ""
            visible.append({
                "provider": row["provider"],
                "contact_id": row["contact_id"] or None,
                "connected": True,
                "account_label": row["account_label"],
                "destination_label": destination,
                "connected_at": row["connected_at"],
            })
        return visible

    def _rows(self) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT provider, contact_id, account_label, destination_label, secret, secret_kind
                FROM platform_connections
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def _pick(self, rows: list) -> Optional[Dict[str, str]]:
        order = ("slack", "teams", "email_microsoft", "email_google")
        by_provider = {row["provider"]: row for row in rows}
        for provider in order:
            row = by_provider.get(provider)
            if row is None:
                continue
            return {
                "provider": provider,
                "account_label": row["account_label"],
                "destination_label": row["destination_label"],
                "secret": row["secret"],
                "secret_kind": row["secret_kind"],
            }
        return None

    def destination_for(self, contact_id: str = "") -> Optional[Dict[str, str]]:
        """One platform for this responder, else the workspace connection.

        Order is Slack, then Teams, then email. A responder who has connected
        their own account is not paged on the workspace account.
        """
        rows = self._rows()
        wanted = (contact_id or "").strip()
        if wanted:
            personal = self._pick([row for row in rows if (row["contact_id"] or "") == wanted])
            if personal is not None:
                return personal
        return self._pick([row for row in rows if not (row["contact_id"] or "")])

    def first_destination(self) -> Optional[Dict[str, str]]:
        return self.destination_for("")


def message_text(title: str, summary: str, link: str) -> str:
    body = (summary or "").strip()
    if len(body) > 400:
        body = body[:400].rstrip() + "..."
    return f"{title}\n\n{body}\n\n{link}".strip()


async def deliver(connection: Dict[str, str], text: str, client: Optional[httpx.AsyncClient] = None) -> DispatchResult:
    """Post one message to the connected platform. The secret is not logged."""
    owns = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=20.0)
    provider = connection["provider"]
    try:
        if connection["secret_kind"] == "webhook":
            response = await client.post(connection["secret"], json={"text": text})
            ok = response.status_code == 200
            error = "" if ok else f"http_{response.status_code}"
        elif provider == "email_microsoft":
            ok, error = await _graph_mail(client, connection["secret"], connection["account_label"], text)
        elif provider == "email_google":
            ok, error = await _gmail(client, connection["secret"], connection["account_label"], text)
        elif provider == "teams":
            ok, error = await _teams(client, connection["secret"], connection.get("destination_label") or "", text)
        else:
            ok, error = False, "unsupported"
    except Exception:
        ok, error = False, "unreachable"
    finally:
        if owns:
            await client.aclose()
    channel = {
        "slack": ChannelType.WEBHOOK,
        "teams": ChannelType.WEBHOOK,
        "email_microsoft": ChannelType.WEBHOOK,
        "email_google": ChannelType.WEBHOOK,
    }.get(provider, ChannelType.WEBHOOK)
    return DispatchResult(
        channel=channel,
        success=ok,
        recipient=connection.get("destination_label") or connection.get("account_label") or provider,
        error=None if ok else error,
    )


async def _graph_mail(client, token: str, mailbox: str, text: str):
    subject, _, body = text.partition("\n\n")
    response = await client.post(
        "https://graph.microsoft.com/v1.0/me/sendMail",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        json={
            "message": {
                "subject": subject or "Aegis alert",
                "body": {"contentType": "Text", "content": body or text},
                "toRecipients": [{"emailAddress": {"address": mailbox}}],
            }
        },
    )
    if response.status_code in (200, 202):
        return True, ""
    return False, f"http_{response.status_code}"


async def _gmail(client, token: str, mailbox: str, text: str):
    import base64
    subject, _, body = text.partition("\n\n")
    raw_msg = f"To: {mailbox}\r\nSubject: {subject or 'Aegis alert'}\r\n\r\n{body or text}"
    raw = base64.urlsafe_b64encode(raw_msg.encode("utf-8")).decode("ascii")
    response = await client.post(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        json={"raw": raw},
    )
    if response.status_code == 200:
        return True, ""
    return False, f"http_{response.status_code}"


async def _teams(client, token: str, destination: str, text: str):
    if "/" not in destination:
        return False, "no_channel"
    team_id, channel_id = destination.split("/", 1)
    response = await client.post(
        f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        json={"body": {"contentType": "text", "content": text}},
    )
    if response.status_code in (200, 201):
        return True, ""
    return False, f"http_{response.status_code}"


async def exchange_code(provider: str, base_url: str, code: str, client: Optional[httpx.AsyncClient] = None) -> Optional[Dict[str, str]]:
    """Trade the provider's code for a stored connection. Returns None when it is not usable."""
    creds = app_credentials(provider)
    if creds is None or not code:
        return None
    client_id, secret = creds
    redirect = redirect_uri(base_url, provider)
    owns = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=20.0)
    try:
        if provider == "slack":
            response = await client.post(
                "https://slack.com/api/oauth.v2.access",
                data={"client_id": client_id, "client_secret": secret, "code": code, "redirect_uri": redirect},
            )
            return slack_connection(response.json())
        if provider in ("teams", "email_microsoft"):
            response = await client.post(
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                data={
                    "client_id": client_id,
                    "client_secret": secret,
                    "code": code,
                    "redirect_uri": redirect,
                    "grant_type": "authorization_code",
                },
            )
            token_body = response.json()
            access = str(token_body.get("access_token") or "")
            profile = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": "Bearer " + access},
            )
            me = profile.json() if profile.status_code == 200 else {}
            mail = str(me.get("mail") or me.get("userPrincipalName") or "")
            name = str(me.get("displayName") or mail or "Microsoft")
            destination = ""
            if provider == "teams" and access:
                destination = await _first_teams_channel(client, access)
            refresh = str(token_body.get("refresh_token") or "")
            if provider == "teams":
                if not destination:
                    return None
                return bearer_connection(name, destination, access, refresh)
            if not mail:
                return None
            return bearer_connection(mail, mail, access, refresh)
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": client_id,
                "client_secret": secret,
                "code": code,
                "redirect_uri": redirect,
                "grant_type": "authorization_code",
            },
        )
        token_body = response.json()
        access = str(token_body.get("access_token") or "")
        profile = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": "Bearer " + access},
        )
        me = profile.json() if profile.status_code == 200 else {}
        mail = str(me.get("email") or "")
        if not mail:
            return None
        return bearer_connection(mail, mail, access, str(token_body.get("refresh_token") or ""))
    except Exception:
        return None
    finally:
        if owns:
            await client.aclose()


async def _first_teams_channel(client, access: str) -> str:
    headers = {"Authorization": "Bearer " + access}
    teams = await client.get("https://graph.microsoft.com/v1.0/me/joinedTeams", headers=headers)
    if teams.status_code != 200:
        return ""
    values = (teams.json() or {}).get("value") or []
    if not values:
        return ""
    team_id = str(values[0].get("id") or "")
    channels = await client.get(
        f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels",
        headers=headers,
    )
    if channels.status_code != 200 or not team_id:
        return ""
    listed = (channels.json() or {}).get("value") or []
    if not listed:
        return ""
    channel_id = str(listed[0].get("id") or "")
    if not channel_id:
        return ""
    return team_id + "/" + channel_id
