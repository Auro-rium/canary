# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""WP3 conversation loop: persistence, stop conditions, monitors, alerts."""

from __future__ import annotations

import asyncio

import pytest
from engine_support import _key, build, factory, metrics, new_campaign_id  # noqa: F401
from fixtures.fake_target import FakeTarget

from cyberredteam.engine import PlannedTurn, run_campaign
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo, CampaignRepo


def _run(h, campaign_id):
    return asyncio.run(run_campaign(h.request, campaign_id, h.deps))


def _only_conversation(h, outcome):
    assert len(outcome.conversations) == 1
    return h.conversations.get(outcome.conversations[0].conversation_id, raw=True, actor="test")


def test_full_transcript_persisted_turn_by_turn(factory):
    h = build(factory, max_turns=4)
    cid_seen: list[tuple[int, int]] = []

    def check_db(event_type, payload):
        if event_type == "turn":
            conv = h.conversations.get(payload.conversation_id)
            cid_seen.append((payload.index, len(conv.turns)))

    h.events.hook = check_db
    campaign = new_campaign_id()
    outcome = _run(h, campaign)

    # Each turn was already in the DB when its event was emitted.
    assert cid_seen == [(0, 1), (1, 2), (2, 3), (3, 4)]
    conv = _only_conversation(h, outcome)
    assert conv.status == "completed"
    assert [t.message for t in conv.turns] == [f"hello turn {i}" for i in range(4)]
    assert all(t.response_text and t.http_status == 200 for t in conv.turns)
    assert outcome.status == "completed"
    assert CampaignRepo(factory).get(campaign).status == "completed"
    types = [t for t, _ in h.events.events]
    assert types[0] == "campaign_started" and types[-1] == "campaign_complete"
    assert types.count("turn") == 4 and "conversation_started" in types


def test_max_turns_stops(factory):
    h = build(factory, max_turns=2)
    outcome = _run(h, new_campaign_id())
    conv = _only_conversation(h, outcome)
    assert conv.status == "completed" and len(conv.turns) == 2
    assert len(h.fake.requests) == 2


def test_planner_none_ends_conversation(factory):
    h = build(factory, max_turns=8, planner_kwargs={"end_at": 1})
    conv = _only_conversation(h, _run(h, new_campaign_id()))
    assert conv.status == "completed" and len(conv.turns) == 1


def test_crash_mid_conversation_keeps_earlier_turns(factory):
    h = build(factory, max_turns=6, planner_kwargs={"raise_at": 2})
    outcome = _run(h, new_campaign_id())
    conv = _only_conversation(h, outcome)
    assert conv.status == "error"
    assert [t.index for t in conv.turns] == [0, 1]
    finished = h.events.of_type("conversation_finished")
    assert finished[0].status == "error"


def test_budget_stop_mid_conversation(factory):
    h = build(factory, max_turns=8, max_total_requests=3)
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    conv = _only_conversation(h, outcome)
    assert conv.status == "stopped_budget" and len(conv.turns) == 3
    assert BudgetLedgerRepo(factory).total(campaign, "requests") == 3
    assert outcome.requests_used == 3
    assert h.events.of_type("budget_update")[-1].requests_used == 3


def test_llm_cost_budget_stop(factory):
    h = build(factory, max_turns=8, max_llm_cost_usd=1.0,
              planner_kwargs={"cost_usd": 0.4, "tokens": 100})
    campaign = new_campaign_id()
    conv = _only_conversation(h, _run(h, campaign))
    assert conv.status == "stopped_budget" and len(conv.turns) == 3
    totals = BudgetLedgerRepo(factory).totals(campaign)
    assert totals["tokens"] == 300 and abs(totals["usd"] - 1.2) < 1e-9


def test_cancel_mid_conversation(factory):
    h = build(factory, max_turns=8)
    campaign = new_campaign_id()

    async def on_event(event_type, payload):
        if event_type == "turn" and payload.index == 1:
            await h.control.cancel(campaign)

    h.events.hook = on_event
    outcome = _run(h, campaign)
    conv = _only_conversation(h, outcome)
    assert conv.status == "cancelled" and len(conv.turns) == 2
    assert outcome.status == "cancelled"
    assert CampaignRepo(factory).get(campaign).status == "cancelled"
    assert h.events.of_type("campaign_cancelled")[0].reason == "user"


def test_run_control_failure_fails_closed(factory):
    h = build(factory, max_turns=4)

    class Broken:
        async def check(self, campaign_id):
            raise ConnectionError("control store down")

    h.deps.run_control = Broken()
    conv = _only_conversation(h, _run(h, new_campaign_id()))
    assert conv.status == "stopped_killed" and conv.turns == []
    assert h.fake.requests == []


def test_error_streak_of_three_stops(factory, metrics):
    fake = FakeTarget(profile="flaky_500", fail_first=1000)
    h = build(factory, fake=fake, max_turns=8)
    campaign = new_campaign_id()
    conv = _only_conversation(h, _run(h, campaign))
    assert conv.status == "stopped_target_error_streak"
    assert len(conv.turns) == 3
    assert all(t.error and t.error.startswith("http_5xx") for t in conv.turns)
    # Retries are real requests and are charged to the budget.
    assert BudgetLedgerRepo(factory).total(campaign, "requests") == len(fake.requests) == 9
    assert any("error streak" in title for title, _, _ in metrics.alerts)


def test_error_streak_resets_on_success(factory):
    # Requests 1-3 fail (turn 0 exhausts its retries), then fail every 4th.
    fake = FakeTarget(profile="flaky_500", fail_first=3, fail_every=4)
    h = build(factory, fake=fake, max_turns=5)
    conv = _only_conversation(h, _run(h, new_campaign_id()))
    assert conv.status == "completed" and len(conv.turns) == 5
    assert conv.turns[0].error and conv.turns[-1].error is None


def test_critical_canary_leak_stops_immediately_and_alerts(factory, metrics):
    fake = FakeTarget(profile="leaks_after_n_turns", n_turns=1)
    h = build(factory, fake=fake, max_turns=8)
    h.deps.canary_values = (fake.canary,)
    notified = []

    async def on_call(alert):
        notified.append(alert)

    h.deps.on_call = on_call
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    conv = _only_conversation(h, outcome)
    assert conv.status == "stopped_monitor"
    assert len(conv.turns) == 2 and len(fake.requests) == 2
    assert conv.turns[1].monitor_hits == ["canary_leak"]
    assert conv.turns[0].monitor_hits == []

    # Alert and on-call fired, carrying ids and hit names but no evidence.
    assert [lvl for _, _, lvl in metrics.alerts] == ["ERROR"]
    assert fake.canary not in metrics.alerts[0][1]
    assert len(notified) == 1 and notified[0].hits == ["canary_leak"]
    assert notified[0].turn_index == 1 and notified[0].campaign_id == campaign

    hit = h.events.of_type("monitor_hit")[0]
    assert hit.severity == "critical" and hit.stops_conversation
    # The canary never reaches the SSE preview or the redacted stored preview.
    assert all(fake.canary not in p.response_preview for p in h.events.of_type("turn"))
    redacted = h.conversations.get(conv.conversation_id)
    assert fake.canary not in redacted.turns[1].response_text


def test_forbidden_structured_tool_call_is_critical(factory, metrics):
    fake = FakeTarget(profile="tool_misuse_on_turn_k", k=2)
    h = build(factory, fake=fake, max_turns=8)
    h.deps.forbidden_tools = frozenset({fake.forbidden_tool})
    conv = _only_conversation(h, _run(h, new_campaign_id()))
    assert conv.status == "stopped_monitor" and len(conv.turns) == 2
    assert conv.turns[1].monitor_hits == ["forbidden_tool_call"]
    assert metrics.alerts


def test_forbidden_tool_allowed_when_destructive_tools_allowed(factory):
    fake = FakeTarget(profile="tool_misuse_on_turn_k", k=2)
    h = build(factory, fake=fake, max_turns=4, allow_destructive_tools=True)
    h.deps.forbidden_tools = frozenset({fake.forbidden_tool})
    conv = _only_conversation(h, _run(h, new_campaign_id()))
    assert conv.status == "completed" and len(conv.turns) == 4
    assert all(t.monitor_hits == [] for t in conv.turns)


def test_broken_monitor_fails_closed_and_keeps_turn(factory):
    h = build(factory, max_turns=4)

    class Broken:
        async def check(self, turn, context):
            raise ValueError("detector bug")

    h.deps.monitors = [Broken()]
    conv = _only_conversation(h, _run(h, new_campaign_id()))
    assert conv.status == "stopped_monitor" and len(conv.turns) == 1
    assert conv.turns[0].monitor_hits == ["monitor_error:Broken"]


def test_campaign_header_on_every_request(factory):
    fake = FakeTarget(profile="flaky_500", fail_first=1, fail_every=3)
    h = build(factory, fake=fake, max_turns=4, techniques=["technique_a", "technique_b"],
              trials_per_technique=2)
    campaign = new_campaign_id()
    _run(h, campaign)
    assert len(fake.requests) > 8
    assert {r.headers.get("x-canary-campaign") for r in fake.requests} == {campaign}


def test_metrics_logged_per_turn(factory, metrics):
    h = build(factory, max_turns=3)
    campaign = new_campaign_id()
    _run(h, campaign)
    assert metrics.started == [campaign]
    assert [step for _, _, step in metrics.logs] == [1, 2, 3]
    last = metrics.logs[-1][1]
    assert last["turns_total"] == 3 and last["requests_total"] == 3
    assert set(last) == {"turns_total", "requests_total", "budget_remaining_pct", "monitor_hits"}
    assert metrics.finished[0][1]["status"] == "completed"


def test_event_sink_failure_never_breaks_run(factory):
    h = build(factory, max_turns=2)

    def boom(event_type, payload):
        raise RuntimeError("sink down")

    h.events.hook = boom
    conv = _only_conversation(h, _run(h, new_campaign_id()))
    assert conv.status == "completed" and len(conv.turns) == 2


def test_end_conversation_flag_ends_without_sending(factory):
    with pytest.raises(ValueError):
        PlannedTurn(message="  ")
    h = build(factory, max_turns=8)

    class EndsAfterOne:
        async def next_turn(self, state):
            if state.turns:
                return PlannedTurn(end_conversation=True)  # empty message is fine here
            return PlannedTurn(message="hello turn 0")

    h.deps.planner_factory = lambda spec: EndsAfterOne()
    conv = _only_conversation(h, _run(h, new_campaign_id()))
    assert conv.status == "completed" and len(conv.turns) == 1
    assert len(h.fake.requests) == 1
