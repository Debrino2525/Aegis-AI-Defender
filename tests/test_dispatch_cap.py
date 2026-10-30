"""Outside channels stop after the hourly cap, and the held count stays visible."""

import asyncio
from datetime import datetime, timezone

from aegis.alerting.cap import DispatchCap
from aegis.alerting.models import (
    AssetOwnerMapping,
    ChannelType,
    DispatchResult,
    OnCallContact,
)
from aegis.alerting.queue import AlertQueue
from aegis.alerting.router import AlertRouter


class _Sender:
    def __init__(self, ok=True):
        self.ok = ok
        self.sent = []

    async def deliver(self, connection, text, client=None):
        self.sent.append(text.split("\n", 1)[0])
        return DispatchResult(channel=ChannelType.WEBHOOK, success=self.ok, recipient="#soc")


def _router(tmp_path, sender, monkeypatch):
    queue = AlertQueue(tmp_path / "alerts.sqlite3")
    router = AlertRouter(queue=queue)
    router.cap.set_hourly_cap(2)
    router.platforms.save("slack", "", {
        "account_label": "Acme",
        "destination_label": "#soc",
        "secret": "https://example.test/hook",
        "secret_kind": "webhook",
    })
    monkeypatch.setattr("aegis.alerting.router.deliver", sender.deliver)
    router.escalation.add_contact(OnCallContact(contact_id="ops", name="Ops", phone="+15555550100"))
    router.escalation.add_owner_mapping(AssetOwnerMapping(
        cidr_or_host="10.8.0.0/16",
        environment="Lab",
        owner_team="SOC",
        primary_contact_id="ops",
        escalation_contact_id="ops",
    ))
    return router


def _event(ip):
    return {
        "pattern_id": "AEGIS-BEH-002",
        "title": "C2 Beaconing Pattern",
        "severity": "CRITICAL",
        "source_ip": ip,
        "dest_ip": "203.0.113.10",
        "dest_port": 4444,
        "tactic": "Command and Control",
    }


def test_cap_persists_and_clamps(tmp_path):
    queue = AlertQueue(tmp_path / "alerts.sqlite3")
    cap = DispatchCap(queue)
    assert cap.set_hourly_cap(0) == 1
    assert cap.set_hourly_cap(500) == 100
    cap.set_hourly_cap(2)
    moment = datetime(2026, 10, 30, 15, 0, tzinfo=timezone.utc)
    assert cap.reserve(moment) == "page"
    assert cap.reserve(moment) == "page"
    assert cap.reserve(moment) == "summary"
    assert cap.reserve(moment) == "hold"
    reloaded = DispatchCap(AlertQueue(queue.db_path))
    picture = reloaded.snapshot(moment)
    assert picture["sent_this_hour"] == 2
    assert picture["summary_sent"] is True
    assert picture["hourly_cap"] == 2


def test_router_pages_then_summarizes_and_holds(tmp_path, monkeypatch):
    sender = _Sender()
    router = _router(tmp_path, sender, monkeypatch)

    async def run():
        for host in ("10.8.0.1", "10.8.0.2", "10.8.0.3", "10.8.0.4"):
            routed = await router.route_behavioral_alert(_event(host))
            assert routed is not None
        await router.route_behavioral_alert(_event("10.8.0.1"))

    asyncio.run(run())
    assert sender.sent[:2] == ["C2 Beaconing Pattern", "C2 Beaconing Pattern"]
    assert sender.sent[2] == "Outside channel cap reached"
    assert len(sender.sent) == 3
    picture = router.cap.snapshot()
    assert picture["sent_this_hour"] == 2
    assert picture["summary_sent"] is True
    assert picture["held_this_hour"] == 3
    rows = {row["source_ip"]: row for row in router.queue.list_recent_alerts()}
    assert rows["10.8.0.1"]["paged"] == 1
    assert rows["10.8.0.1"]["held_count"] == 1
    assert rows["10.8.0.3"]["paged"] == 0
    assert rows["10.8.0.3"]["held_count"] == 1
    restored = DispatchCap(AlertQueue(router.queue.db_path)).snapshot()
    assert restored["sent_this_hour"] == 2
    assert restored["held_this_hour"] == 3


def test_failed_page_does_not_use_up_the_cap(tmp_path, monkeypatch):
    sender = _Sender(ok=False)
    router = _router(tmp_path, sender, monkeypatch)
    router.cap.set_hourly_cap(1)

    async def run():
        await router.route_behavioral_alert(_event("10.8.1.1"))
        sender.ok = True
        await router.route_behavioral_alert(_event("10.8.1.2"))

    asyncio.run(run())
    assert router.cap.snapshot()["sent_this_hour"] == 1
    assert sender.sent[-1] == "C2 Beaconing Pattern"
