# ruff: noqa: F811
"""Control-plane API: cancel, kill switch, auth, audit rows, SSE Last-Event-ID replay."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from jobs_support import FakeRunner, db_factory, seed_campaign  # noqa: F401

from cyberredteam.api import app, require_auth, settings
from cyberredteam.jobs.api_v2 import ControlPlane, get_control_plane
from cyberredteam.jobs.control import DbRunControl
from cyberredteam.observability import hooks
from cyberredteam.storage.v2.repositories import AuditRepo, CampaignRepo


@pytest.fixture
def plane(db_factory):
    p = ControlPlane(db_factory, poll_interval_s=0.01)
    app.dependency_overrides[get_control_plane] = lambda: p
    yield p
    app.dependency_overrides.pop(get_control_plane, None)


@pytest.fixture
def client(plane):
    return TestClient(app)


def test_cancel_stops_one_campaign_not_the_other(db_factory, plane, client):
    a = seed_campaign(db_factory, status="running")
    b = seed_campaign(db_factory, status="running")
    control = DbRunControl(db_factory, cache_ttl=0)

    async def go():
        ra = FakeRunner(db_factory, control, conversations=3, turns=40, delay=0.02)
        rb = FakeRunner(db_factory, control, conversations=3, turns=40, delay=0.02)
        ta = asyncio.create_task(ra(None, a))
        tb = asyncio.create_task(rb(None, b))
        await asyncio.sleep(0.15)
        resp = await asyncio.to_thread(client.post, f"/api/v2/campaigns/{a}/cancel")
        assert resp.status_code == 200 and resp.json()["status"] == "cancelling"
        await asyncio.wait_for(asyncio.gather(ta, tb), 10)
        return ra, rb

    ra, rb = asyncio.run(go())
    assert set(ra.stopped.values()) == {"cancelled"} and len(ra.stopped) == 3
    assert rb.stopped == {}  # the other campaign ran to completion
    assert len([s for s in rb.sent]) == 3 * 40
    audit = AuditRepo(db_factory).list(action="campaign.cancel")
    assert [e.object for e in audit] == [f"campaign:{a}"]


def test_cancel_unknown_and_terminal(db_factory, client):
    assert client.post("/api/v2/campaigns/nope/cancel").status_code == 404
    done = seed_campaign(db_factory, status="completed")
    assert client.post(f"/api/v2/campaigns/{done}/cancel").status_code == 409


def test_cancel_queued_campaign_is_cancelled_immediately(db_factory, client):
    cid = seed_campaign(db_factory)
    assert client.post(f"/api/v2/campaigns/{cid}/cancel").json()["status"] == "cancelled"
    assert CampaignRepo(db_factory).get(cid).status == "cancelled"


def test_kill_switch_endpoint_audits_and_alerts(db_factory, client, monkeypatch):
    alerts = []

    class M(hooks.NoopMetrics):
        def alert(self, title, text, level="WARN"):
            alerts.append((title, level))

    monkeypatch.setattr(hooks, "_metrics", M())
    assert client.get("/api/v2/admin/kill-switch").json()["enabled"] is False
    on = client.post("/api/v2/admin/kill-switch", json={"enabled": True}).json()
    assert on["enabled"] is True and on["db"] is True
    assert client.get("/api/v2/admin/kill-switch").json()["enabled"] is True
    assert len(alerts) == 1
    off = client.post("/api/v2/admin/kill-switch", json={"enabled": False}).json()
    assert off["enabled"] is False
    assert len(alerts) == 1  # only activation alerts
    rows = AuditRepo(db_factory).list(action="kill_switch.set")
    assert [r.details["enabled"] for r in rows] == [True, False]


def test_kill_switch_env_reported(client, monkeypatch):
    monkeypatch.setenv("CANARY_KILL_SWITCH", "1")
    view = client.get("/api/v2/admin/kill-switch").json()
    assert view["enabled"] is True and view["env"] is True and view["db"] is False


def test_control_endpoints_require_auth(db_factory, plane):
    app.dependency_overrides.pop(require_auth, None)
    original = settings.api_secret_key
    settings.api_secret_key = "s3cret"
    try:
        c = TestClient(app)
        cid = seed_campaign(db_factory, status="running")
        calls = [
            ("post", f"/api/v2/campaigns/{cid}/cancel", None),
            ("post", "/api/v2/admin/kill-switch", {"enabled": True}),
            ("get", "/api/v2/admin/kill-switch", None),
            ("get", f"/api/v2/campaigns/{cid}/events", None),
        ]
        for method, url, body in calls:
            assert getattr(c, method)(url, **({"json": body} if body else {})).status_code == 401
            bad = {"Authorization": "Bearer nope"}
            assert getattr(c, method)(url, headers=bad, **({"json": body} if body else {})).status_code == 401
        # nothing was written by the rejected calls
        assert AuditRepo(db_factory).list() == []
        ok = {"Authorization": "Bearer s3cret"}
        assert c.post("/api/v2/admin/kill-switch", json={"enabled": False}, headers=ok).status_code == 200
        assert len(AuditRepo(db_factory).list(action="kill_switch.set")) == 1
    finally:
        settings.api_secret_key = original
        app.dependency_overrides[require_auth] = lambda: None


def _parse_sse(text: str) -> list[tuple[int, str]]:
    out = []
    for block in text.strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "id" in fields:
            out.append((int(fields["id"]), fields["event"]))
    return out


def test_sse_last_event_id_replay(db_factory, plane, client):
    cid = seed_campaign(db_factory, status="running")
    for i in range(5):
        plane.events.append(cid, "turn", {"n": i})
    plane.events.append(cid, "campaign_completed", {"status": "completed"})
    CampaignRepo(db_factory).set_status(cid, "completed")

    full = _parse_sse(client.get(f"/api/v2/campaigns/{cid}/events").text)
    assert [s for s, _ in full] == [1, 2, 3, 4, 5, 6]

    resumed = _parse_sse(
        client.get(f"/api/v2/campaigns/{cid}/events", headers={"Last-Event-ID": "3"}).text
    )
    assert [s for s, _ in resumed] == [4, 5, 6]
    assert resumed[-1][1] == "campaign_completed"

    assert client.get(
        f"/api/v2/campaigns/{cid}/events", headers={"Last-Event-ID": "abc"}
    ).status_code == 400
    assert client.get("/api/v2/campaigns/missing/events").status_code == 404


def test_sse_streams_live_events_and_disconnect_is_harmless(db_factory, plane, client):
    cid = seed_campaign(db_factory, status="running")
    plane.events.append(cid, "turn", {"n": 0})
    import threading
    import time

    def later():
        time.sleep(0.1)
        plane.events.append(cid, "turn", {"n": 1})
        plane.events.append(cid, "campaign_completed", {})

    t = threading.Thread(target=later)
    t.start()
    seen = _parse_sse(client.get(f"/api/v2/campaigns/{cid}/events").text)
    t.join()
    assert [s for s, _ in seen] == [1, 2, 3]
    # a client that read one event and left changed nothing about the campaign
    assert CampaignRepo(db_factory).get(cid).status == "running"
