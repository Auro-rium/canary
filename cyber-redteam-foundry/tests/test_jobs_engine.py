"""The real WP3 engine through the worker path (execute_campaign), end to end.

FakeTarget over httpx.MockTransport, a benign scripted planner, SQLite or
Postgres. Checks events (contract round trip, no double emission), cancel,
kill switch and the fail-closed "no planner configured" path.
"""

from __future__ import annotations

import asyncio
from collections import Counter

from engine_support import ScriptedPlanner, build, new_campaign_id

from cyberredteam.contracts import SSE_EVENT_TYPES, parse_sse_event
from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.execution import JobRuntime, execute_campaign
from cyberredteam.jobs.runner_wiring import load_planner_factory, make_runner
from cyberredteam.storage.v2.repositories import (
    AuditRepo,
    CampaignRepo,
    ConversationRepo,
    SqlTargetStore,
)


class HookPlanner(ScriptedPlanner):
    def __init__(self, on_turn):
        super().__init__()
        self._on_turn = on_turn

    async def next_turn(self, state):
        self._on_turn()
        return await super().next_turn(state)


def _setup(factory, *, on_turn=None, planner=True, **build_kw):
    h = build(factory, **build_kw)
    SqlTargetStore(factory).set_verified(h.request.target.target_id, "header")
    cid = new_campaign_id()
    CampaignRepo(factory).create(cid, h.request.target.target_id, h.request.policy)
    control = DbRunControl(factory)  # production defaults
    rt = JobRuntime(factory=factory, runner=None, control=control, heartbeat_interval_s=0.05)
    turns = Counter()

    def counting():
        turns["n"] += 1
        if on_turn is not None:
            on_turn(rt, cid, turns["n"])

    factory_fn = (lambda spec: HookPlanner(counting)) if planner else None
    rt.runner = make_runner(
        rt, factory_fn,
        engine_options={
            "adapter_factory": h.deps.adapter_factory,
            "rate_limiter": h.deps.rate_limiter,
            "clock": h.deps.clock,
        },
    )
    return rt, cid, turns


def _events(rt, cid):
    evs = rt.events.since(cid)
    for e in evs:  # every stored event round-trips through the contract parser
        assert e.type in SSE_EVENT_TYPES
        assert parse_sse_event(e.to_sse().split("data: ", 1)[1].strip()).seq == e.seq
    return evs


def test_full_campaign_through_worker_path(db_factory):
    rt, cid, turns = _setup(db_factory, techniques=["a", "b"], max_turns=3)
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    assert CampaignRepo(db_factory).get(cid).status == "completed"
    convs = ConversationRepo(db_factory)
    ids = convs.list_for_campaign(cid)
    assert len(ids) == 2 and all(len(convs.get(i).turns) == 3 for i in ids)
    types = Counter(e.type for e in _events(rt, cid))
    assert types["campaign_started"] == 1 and types["campaign_complete"] == 1  # no double emission
    assert types["turn"] == 6 and sum(types[t] for t in
                                      ("campaign_cancelled", "campaign_failed")) == 0
    turn_ev = next(e for e in _events(rt, cid) if e.type == "turn")
    assert len(turn_ev.payload.message_preview) <= 280


def test_cancel_stops_real_engine_within_one_turn(db_factory):
    def trigger(rt, cid, n):
        if n == 3:
            rt.control.store.request_cancel(cid, "test")

    rt, cid, turns = _setup(db_factory, techniques=["a", "b"], max_turns=10, on_turn=trigger)
    assert asyncio.run(execute_campaign(rt, cid)) == "cancelled"
    assert turns["n"] <= 3 + 2  # planner calls after the flag: at most one per conversation
    evs = _events(rt, cid)
    cancelled = [e for e in evs if e.type == "campaign_cancelled"]
    assert len(cancelled) == 1 and cancelled[0].payload.reason == "user"
    assert [e.type for e in evs].count("campaign_started") == 1
    assert not any(e.type == "campaign_complete" for e in evs)
    assert CampaignRepo(db_factory).get(cid).status == "cancelled"


def test_kill_switch_stops_real_engine(db_factory):
    def trigger(rt, cid, n):
        if n == 3:
            rt.control.store.set_kill_switch(True, "test")

    rt, cid, turns = _setup(db_factory, techniques=["a", "b"], max_turns=10, on_turn=trigger)
    assert asyncio.run(execute_campaign(rt, cid)) == "cancelled"
    assert turns["n"] <= 3 + 2
    evs = _events(rt, cid)
    cancelled = [e for e in evs if e.type == "campaign_cancelled"]
    assert len(cancelled) == 1 and cancelled[0].payload.reason == "kill_switch"
    assert CampaignRepo(db_factory).get(cid).status == "cancelled"  # terminal
    assert AuditRepo(db_factory).list(action="campaign.killed")


def test_no_planner_configured_fails_closed(db_factory):
    rt, cid, _ = _setup(db_factory, planner=False)
    assert asyncio.run(execute_campaign(rt, cid)) == "failed"
    evs = _events(rt, cid)
    assert [e.type for e in evs] == ["campaign_failed"]
    assert evs[0].payload.message == "NoPlannerConfigured"
    assert CampaignRepo(db_factory).get(cid).status == "failed"


def test_load_planner_factory():
    assert load_planner_factory(None) is None
    assert load_planner_factory("engine_support:ScriptedPlanner") is ScriptedPlanner
