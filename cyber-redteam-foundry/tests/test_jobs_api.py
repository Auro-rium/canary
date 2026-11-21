"""Control-plane API: cancel, kill switch, auth, audit rows, SSE Last-Event-ID replay."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from jobs_support import FakeRunner, seed_campaign

from cyberredteam.api import app
from cyberredteam.contracts import (
    BudgetUpdatePayload,
    CampaignCompletePayload,
    TurnPayload,
    parse_sse_event,
)
from cyberredteam.jobs.api_v2 import ControlPlane, get_control_plane
from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.events import EventLogSink
from cyberredteam.observability import hooks
from cyberredteam.storage.v2.repositories import AuditRepo, CampaignRepo


@pytest.fixture
def plane(db_factory):
    p = ControlPlane(db_factory, poll_interval_s=0.01)
    app.dependency_overrides[get_control_plane] = lambda: p
    yield p
    app.dependency_overrides.pop(get_control_plane, None)


@pytest.fixture
def client(plane, v2):
    """Signed in as org A's admin with a real API key."""
    return TestClient(app, headers=v2.h("admin"))


@pytest.fixture
def seed(v2, db_factory):
    """seed_campaign in org A (the signed-in admin's org)."""
    return lambda **kw: seed_campaign(db_factory, org_id=v2.orgs["a"], **kw)


def test_cancel_stops_one_campaign_not_the_other(db_factory, plane, client, seed):
    a = seed(status="running")
    b = seed(status="running")
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


def test_cancel_unknown_and_terminal(db_factory, client, seed):
    assert client.post("/api/v2/campaigns/nope/cancel").status_code == 404
    done = seed(status="completed")
    assert client.post(f"/api/v2/campaigns/{done}/cancel").status_code == 409


def test_cancel_queued_campaign_is_cancelled_immediately(db_factory, client, seed):
    cid = seed()
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


def test_control_endpoints_require_auth(db_factory, plane, v2, seed):
    c = TestClient(app)
    cid = seed(status="running")
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
    # an operator may cancel but not flip the kill switch; a viewer may do neither
    op = v2.h("operator")
    assert c.post("/api/v2/admin/kill-switch", json={"enabled": True}, headers=op).status_code == 403
    assert c.post(f"/api/v2/campaigns/{cid}/cancel", headers=v2.h("viewer")).status_code == 403
    # another org's admin cannot see or cancel this campaign
    assert c.post(f"/api/v2/campaigns/{cid}/cancel", headers=v2.h("admin", "b")).status_code == 404
    assert c.get(f"/api/v2/campaigns/{cid}/events", headers=v2.h("admin", "b")).status_code == 404
    # nothing was written by the rejected calls
    assert AuditRepo(db_factory).list(action="kill_switch.set") == []
    assert AuditRepo(db_factory).list(action="campaign.cancel") == []
    ok = v2.h("admin")
    assert c.post("/api/v2/admin/kill-switch", json={"enabled": False}, headers=ok).status_code == 200
    rows = AuditRepo(db_factory).list(action="kill_switch.set")
    assert [r.actor for r in rows] == [v2.actor("admin").actor]


def _blocks(text: str) -> list[dict]:
    """Parse SSE text into [{id, event: parsed contract model}] via the contract parser."""
    out = []
    for block in text.strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "id" in fields:
            ev = parse_sse_event(fields["data"])  # contract round trip
            assert str(ev.seq) == fields["id"]
            out.append(ev)
    return out


def _budget(cid, n):
    return BudgetUpdatePayload(
        campaign_id=cid, requests_used=n, max_total_requests=100, llm_cost_usd=0, max_llm_cost_usd=1
    )


def _complete(cid):
    return CampaignCompletePayload(
        campaign_id=cid, conversations=1, confirmed=0, duration_seconds=1.0
    )


def test_sse_last_event_id_replay_and_contract_roundtrip(db_factory, plane, client, seed):
    cid = seed(status="running")
    for i in range(5):
        plane.events.append(cid, "budget_update", _budget(cid, i))
    plane.events.append(cid, "campaign_complete", _complete(cid))
    CampaignRepo(db_factory).set_status(cid, "completed")

    full = _blocks(client.get(f"/api/v2/campaigns/{cid}/events").text)
    assert [e.seq for e in full] == [1, 2, 3, 4, 5, 6]
    assert [e.type for e in full][-1] == "campaign_complete"
    assert full[2].payload.requests_used == 2 and full[0].timestamp.tzinfo is not None

    resumed = _blocks(
        client.get(f"/api/v2/campaigns/{cid}/events", headers={"Last-Event-ID": "3"}).text
    )
    assert [e.seq for e in resumed] == [4, 5, 6]

    url = f"/api/v2/campaigns/{cid}/events"
    assert client.get(url, headers={"Last-Event-ID": "abc"}).status_code == 400
    assert client.get(url, headers={"Last-Event-ID": str(2**31)}).status_code == 400
    assert client.get(url, headers={"Last-Event-ID": "-1"}).status_code == 400
    assert client.get(url, headers={"Last-Event-ID": str(2**31 - 1)}).status_code == 200
    assert client.get("/api/v2/campaigns/missing/events").status_code == 404


def test_only_contract_event_types_are_accepted(db_factory, plane, seed):
    cid = seed()
    for bad in ("campaign_completed", "campaign_killed", "campaign_resumed"):
        with pytest.raises(ValueError):
            plane.events.append(cid, bad, {"campaign_id": cid})


def test_cancel_route_event_matches_contract(db_factory, plane, client, seed, v2):
    cid = seed()  # queued -> cancelled immediately
    client.post(f"/api/v2/campaigns/{cid}/cancel")
    (ev,) = _blocks(client.get(f"/api/v2/campaigns/{cid}/events").text)
    assert ev.type == "campaign_cancelled"
    assert ev.payload.campaign_id == cid and ev.payload.reason == "user"
    assert ev.payload.cancelled_by == v2.actor("admin").actor


def test_sink_enforces_preview_cap(db_factory, plane, seed):
    cid = seed()
    long = "x" * 5000
    payload = TurnPayload.model_construct(  # bypasses the validator on purpose
        campaign_id=cid, conversation_id="c", index=0, message_preview=long,
        response_preview=long, tool_call_names=[], http_status=200, latency_ms=1.0,
        monitor_hits=[], error=long,
    )
    asyncio.run(EventLogSink(plane.events).emit("turn", payload))
    (ev,) = plane.events.since(cid)
    assert len(ev.payload.message_preview) <= 280 and ev.payload.message_preview.endswith("…")
    assert len(ev.payload.response_preview) <= 280
    assert len(ev.payload.error) <= 500
    assert parse_sse_event(ev.to_sse().split("data: ", 1)[1].strip()).seq == ev.seq


def test_sse_streams_live_events_and_disconnect_is_harmless(db_factory, plane, client, seed):
    cid = seed(status="running")
    plane.events.append(cid, "budget_update", _budget(cid, 0))
    import threading
    import time

    def later():
        time.sleep(0.1)
        plane.events.append(cid, "budget_update", _budget(cid, 1))
        plane.events.append(cid, "campaign_complete", _complete(cid))

    t = threading.Thread(target=later)
    t.start()
    seen = _blocks(client.get(f"/api/v2/campaigns/{cid}/events").text)
    t.join()
    assert [e.seq for e in seen] == [1, 2, 3]
    # a client that read one event and left changed nothing about the campaign
    assert CampaignRepo(db_factory).get(cid).status == "running"
