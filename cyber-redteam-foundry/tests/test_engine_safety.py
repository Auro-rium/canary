# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""WP3 review regressions: each test probes one safety hole that was found."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from engine_support import _key, build, factory, metrics, new_campaign_id  # noqa: F401
from fixtures.fake_target import FakeTarget

from cyberredteam.contracts import CampaignPolicy, CampaignRequest
from cyberredteam.engine import CampaignRefused, plan_conversations, run_campaign
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo, CampaignRepo, ConversationRepo

CRITICAL = "Canary: critical monitor hit"


def _run(h, campaign_id):
    return asyncio.run(run_campaign(h.request, campaign_id, h.deps))


def _conv(h, campaign_id, i=0):
    spec = plan_conversations(h.request, campaign_id)[i]
    return h.conversations.get(spec.conversation_id, raw=True, actor="test")


def _leaky(factory, **kw):
    fake = FakeTarget(profile="leaks_after_n_turns", n_turns=1)
    h = build(factory, fake=fake, max_turns=8, **kw)
    h.deps.canary_values = (fake.canary,)
    return h, fake


def _critical_alerts(metrics):
    return [a for a in metrics.alerts if a[0] == CRITICAL]


# ── 1. A critical hit is never lost ──────────────────────────────────────────


def test_on_call_raising_cancelled_error_still_stops_terminally(factory, metrics):
    h, fake = _leaky(factory)

    async def on_call(alert):
        raise asyncio.CancelledError()

    h.deps.on_call = on_call
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    assert outcome.conversations[0].status == "stopped_monitor"
    assert _conv(h, campaign).status == "stopped_monitor"
    assert len(fake.requests) == 2
    assert len(_critical_alerts(metrics)) == 1
    assert any(a[0] == "Canary: on-call notification failed" for a in metrics.alerts)


def test_worker_cancel_during_on_call_leaves_terminal_status(factory, metrics):
    h, fake = _leaky(factory)
    entered = asyncio.Event()

    async def on_call(alert):
        entered.set()
        await asyncio.Event().wait()  # hangs until the worker is cancelled

    h.deps.on_call = on_call
    h.deps.hook_timeout_s = 30
    campaign = new_campaign_id()

    async def main():
        task = asyncio.create_task(run_campaign(h.request, campaign, h.deps))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert _conv(h, campaign).status == "stopped_monitor"
    assert len(_critical_alerts(metrics)) == 1
    # A re-run (restarted worker) skips it: no further request.
    h2, _ = _leaky(factory)
    h2.fake = fake
    again = asyncio.run(run_campaign(h.request, campaign, h2.deps))
    assert again.conversations[0].skipped and len(fake.requests) == 2


def test_append_turn_failure_after_critical_hit(factory, metrics):
    h, fake = _leaky(factory)
    notified = []

    async def on_call(alert):
        notified.append(alert)

    class FailingRepo(ConversationRepo):
        def append_turn(self, turn, canary_values=()):
            if turn.monitor_hits:
                raise RuntimeError("db write failed")
            return super().append_turn(turn, canary_values)

    h.deps.repos.conversations = FailingRepo(factory)
    h.deps.on_call = on_call
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    assert outcome.conversations[0].status == "stopped_monitor"
    conv = _conv(h, campaign)
    assert conv.status == "stopped_monitor"
    assert len(conv.turns) == 1  # the leaking turn could not be stored
    assert len(fake.requests) == 2  # no further request
    assert len(_critical_alerts(metrics)) == 1 and len(notified) == 1


def test_resume_rechecks_last_turn_when_stop_status_was_lost(factory, metrics):
    h, fake = _leaky(factory)
    campaign = new_campaign_id()
    _run(h, campaign)
    conv = _conv(h, campaign)
    assert conv.status == "stopped_monitor" and len(conv.turns) == 2
    # Simulate a crash between append_turn and the status write.
    h.conversations.set_status(conv.conversation_id, "running")
    requests = len(fake.requests)

    h2, _ = _leaky(factory)
    h2.deps.canary_values = (fake.canary,)
    notified = []

    async def on_call(alert):
        notified.append(alert)

    h2.deps.on_call = on_call
    outcome = asyncio.run(run_campaign(h.request, campaign, h2.deps))
    assert outcome.conversations[0].status == "stopped_monitor"
    assert _conv(h, campaign).status == "stopped_monitor"
    assert len(fake.requests) == requests  # nothing sent on resume
    assert len(notified) == 1 and notified[0].turn_index == 1
    assert len(_critical_alerts(metrics)) == 2  # original + re-fired on resume


# ── 2. The request budget is exact, auth and retries included ───────────────


def test_budget_cap_counts_every_attempt_and_auth_request(factory):
    seen: list[str] = []
    chat_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal chat_calls
        seen.append(request.url.path)
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "t0k", "expires_in": 3600})
        chat_calls += 1
        if chat_calls % 2:
            return httpx.Response(429, headers={"retry-after": "0"}, json={"error": "slow down"})
        return httpx.Response(500, json={"error": "boom"})

    h = build(
        factory, techniques=["a"], trials_per_technique=2, max_turns=8,
        max_parallel_conversations=2, max_total_requests=4,
        target_overrides={"auth": {"type": "oauth_client_credentials",
                                   "token_url": "http://fake-target.test/token",
                                   "client_id": "c", "client_secret": "s3cret"}},
    )
    h.transport = httpx.MockTransport(handler)
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    assert len(seen) <= 4
    assert "/token" in seen
    assert BudgetLedgerRepo(factory).total(campaign, "requests") == len(seen)
    assert outcome.requests_used == len(seen)
    assert {c.status for c in outcome.conversations} == {"stopped_budget"}


# ── 3. Kill/cancel are honoured after planning and during retries ───────────


def test_kill_during_planning_sends_nothing_more(factory):
    h = build(factory, max_turns=8)

    class KillsWhilePlanning:
        async def next_turn(self, state):
            from cyberredteam.engine import PlannedTurn

            if state.turns:
                await h.control.kill_all()
            return PlannedTurn(message=f"hello turn {len(state.turns)}")

    h.deps.planner_factory = lambda spec: KillsWhilePlanning()
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    assert outcome.conversations[0].status == "stopped_killed"
    assert len(h.fake.requests) == 1
    assert len(_conv(h, campaign).turns) == 1


def test_kill_during_retry_backoff_stops_retries(factory):
    fake = FakeTarget(profile="flaky_500", fail_first=1000)

    async def sleep(seconds):
        await h.control.kill_all()

    h = build(factory, fake=fake, max_turns=8, sleep=sleep)
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    assert outcome.conversations[0].status == "stopped_killed"
    assert len(fake.requests) == 1  # no retry after the kill
    turns = _conv(h, campaign).turns
    assert len(turns) == 1 and turns[0].error  # the one real request is on record


def test_watcher_cancels_adapter_during_long_retry_wait(factory):
    fake = FakeTarget(profile="flaky_500", fail_first=1000)

    async def sleep(seconds):
        asyncio.get_running_loop().call_later(0.02, lambda: asyncio.ensure_future(h.control.kill_all()))
        await asyncio.Event().wait()  # a very long Retry-After / backoff

    h = build(factory, fake=fake, max_turns=8, sleep=sleep)
    h.deps.control_poll_s = 0.01
    campaign = new_campaign_id()

    async def main():
        return await asyncio.wait_for(run_campaign(h.request, campaign, h.deps), 5)

    outcome = asyncio.run(main())
    assert outcome.conversations[0].status == "stopped_killed"
    assert len(fake.requests) == 1


# ── 4. Ledger write failures fail closed ─────────────────────────────────────


def test_ledger_request_write_failure_stops_sending(factory, metrics):
    class FailingLedger(BudgetLedgerRepo):
        calls = 0

        def add(self, campaign_id, kind, amount):
            FailingLedger.calls += 1
            if FailingLedger.calls > 2:
                raise RuntimeError("ledger down")
            return super().add(campaign_id, kind, amount)

    h = build(factory, max_turns=8)
    h.deps.repos.budget = FailingLedger(factory)
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "stopped_budget"
    assert len(h.fake.requests) == 2
    assert any("ledger write failed" in a[0] for a in metrics.alerts)


def test_ledger_llm_write_failure_stops_sending(factory):
    class FailingUsd(BudgetLedgerRepo):
        def add(self, campaign_id, kind, amount):
            if kind == "usd":
                raise RuntimeError("ledger down")
            return super().add(campaign_id, kind, amount)

    h = build(factory, max_turns=8, planner_kwargs={"cost_usd": 0.01})
    h.deps.repos.budget = FailingUsd(factory)
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "stopped_budget"
    assert h.fake.requests == []


# ── 5. Defence in depth at campaign start ────────────────────────────────────


def test_unverified_target_refused_before_any_write(factory):
    h = build(factory, target_overrides={"verified": False})
    campaign = new_campaign_id()
    with pytest.raises(CampaignRefused):
        _run(h, campaign)
    assert CampaignRepo(factory).get(campaign) is None
    assert h.fake.requests == []


def test_production_violation_refused_even_if_validation_bypassed(factory):
    h = build(factory, target_overrides={"environment": "production"}, max_parallel_conversations=2,
              max_total_requests=100)
    bad_policy = CampaignPolicy.model_construct(
        **{**h.request.policy.model_dump(), "max_parallel_conversations": 10}
    )
    bad = CampaignRequest.model_construct(target=h.request.target, policy=bad_policy)
    campaign = new_campaign_id()
    with pytest.raises(CampaignRefused, match="max_parallel_conversations"):
        asyncio.run(run_campaign(bad, campaign, h.deps))
    assert CampaignRepo(factory).get(campaign) is None
    assert h.fake.requests == []


# ── 6. Hooks are bounded by timeouts ─────────────────────────────────────────


def test_hanging_run_control_counts_as_killed(factory):
    h = build(factory, max_turns=4)

    class Hangs:
        async def check(self, campaign_id):
            await asyncio.Event().wait()

    h.deps.run_control = Hangs()
    h.deps.hook_timeout_s = 0.05
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "stopped_killed"
    assert h.fake.requests == []


def test_hanging_on_call_times_out_and_alert_recorded(factory, metrics):
    h, fake = _leaky(factory)

    async def on_call(alert):
        await asyncio.Event().wait()

    h.deps.on_call = on_call
    h.deps.hook_timeout_s = 0.05
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    assert outcome.conversations[0].status == "stopped_monitor"
    assert len(_critical_alerts(metrics)) == 1
    failed = [a for a in metrics.alerts if a[0] == "Canary: on-call notification failed"]
    assert failed and "timed out" in failed[0][1]


def test_hanging_event_sink_does_not_stall_run(factory):
    h = build(factory, max_turns=2)

    async def hang(event_type, payload):
        await asyncio.Event().wait()

    h.events.hook = hang
    h.deps.hook_timeout_s = 0.02
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "completed"
