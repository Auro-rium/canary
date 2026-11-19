# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""WP3 re-review regressions: bypasses of the start checks, unbounded timeouts,
hook-raised CancelledError, unknown control signals, runtime-init failure."""

from __future__ import annotations

import asyncio
import math

import pytest
from engine_support import _key, build, factory, metrics, new_campaign_id  # noqa: F401
from fixtures.fake_target import FakeTarget

from cyberredteam.contracts import CampaignPolicy, CampaignRequest, TargetConfig
from cyberredteam.engine import (
    BudgetLedger,
    CampaignRefused,
    EngineDeps,
    PlannedTurn,
    check_campaign_allowed,
    run_campaign,
)
from cyberredteam.engine import runner as runner_mod
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo, CampaignRepo


def _run(h, campaign_id, request=None):
    return asyncio.run(run_campaign(request or h.request, campaign_id, h.deps))


def _forged(h, *, target=None, **policy_overrides):
    """A CampaignRequest built with model_construct, skipping all validation."""
    t = h.request.target
    tgt = TargetConfig.model_construct(**{**dict(t), **(target or {})})
    pol = CampaignPolicy.model_construct(**{**dict(h.request.policy), **policy_overrides})
    return CampaignRequest.model_construct(target=tgt, policy=pol)


# ── 1. check_campaign_allowed cannot be bypassed ─────────────────────────────


def _refused(h, request):
    campaign = new_campaign_id()
    with pytest.raises(CampaignRefused):
        _run(h, campaign, request)
    assert CampaignRepo(h.factory).get(campaign) is None
    assert h.fake.requests == []


def test_environment_not_exactly_staging_gets_production_rules(factory):
    h = build(factory, max_total_requests=100, max_parallel_conversations=2)
    for env in ("Production", "prod", "", None, "STAGING"):
        _refused(h, _forged(h, target={"environment": env}, max_parallel_conversations=10))
    # Exactly "staging" may use staging limits.
    ok = _forged(h, target={"environment": "staging"}, max_parallel_conversations=10)
    check_campaign_allowed(ok)


@pytest.mark.parametrize("verified", ["no", 1, "true", None])
def test_verified_must_be_exactly_true(factory, verified):
    h = build(factory)
    _refused(h, _forged(h, target={"verified": verified}))


@pytest.mark.parametrize("field,value", [
    ("max_total_requests", math.nan),
    ("max_total_requests", math.inf),
    ("max_total_requests", 0),
    ("max_parallel_conversations", math.nan),
    ("max_parallel_conversations", 2.5),
    ("max_turns", math.nan),
    ("trials_per_technique", True),
    ("rate_limit_rps", math.nan),
    ("rate_limit_rps", -1.0),
    ("max_llm_cost_usd", math.nan),
    ("max_llm_cost_usd", math.inf),
    ("allow_destructive_tools", "no"),
    ("techniques", []),
])
def test_non_finite_or_invalid_limits_refused_in_staging(factory, field, value):
    h = build(factory)
    _refused(h, _forged(h, **{field: value}))


@pytest.mark.parametrize("field", ["rate_limit_rps", "max_parallel_conversations", "max_total_requests"])
def test_production_violations_fail_closed_on_nan(field):
    pol = CampaignPolicy.model_construct(
        techniques=["a"], trials_per_technique=1, max_turns=2, max_parallel_conversations=1,
        rate_limit_rps=1.0, max_total_requests=10, max_llm_cost_usd=1.0,
        stop_on_first_confirmed=False, allow_destructive_tools=False,
    )
    assert pol.production_violations() == []
    bad = pol.model_copy(update={field: math.nan})
    assert any(field in p for p in bad.production_violations())
    truthy = pol.model_copy(update={"allow_destructive_tools": "yes"})
    assert truthy.production_violations()


@pytest.mark.parametrize("cap", [math.nan, math.inf, 0, -5])
def test_ledger_treats_unusable_cap_as_exhausted(factory, cap):
    h = build(factory)
    pol = CampaignPolicy.model_construct(**{**dict(h.request.policy), "max_total_requests": cap})
    ledger = BudgetLedger("c-x", pol, BudgetLedgerRepo(factory))
    assert ledger.exhausted()
    assert asyncio.run(ledger.charge_request()) is False
    assert ledger.remaining_pct() == 0.0


# ── 2. Timeouts are finite and bounded ───────────────────────────────────────


@pytest.mark.parametrize("raw,expected", [
    ("inf", 5.0), ("nan", 5.0), ("-1", 5.0), ("0", 5.0), ("abc", 5.0), ("1e12", 60.0), ("2.5", 2.5),
])
def test_env_hook_timeout_is_finite_and_clamped(monkeypatch, raw, expected):
    monkeypatch.setenv(runner_mod.HOOK_TIMEOUT_ENV, raw)
    assert runner_mod._default_hook_timeout() == expected


def test_engine_deps_validates_timing(factory):
    h = build(factory)
    for name in ("hook_timeout_s", "control_poll_s", "planner_timeout_s", "monitor_timeout_s"):
        for bad in (math.inf, math.nan, 0, -1, "5", True):
            with pytest.raises(ValueError):
                setattr(h.deps, name, bad)
    h.deps.hook_timeout_s = 1e9
    assert h.deps.hook_timeout_s == 60.0
    h.deps.control_poll_s = 0.0001
    assert h.deps.control_poll_s == 0.05
    with pytest.raises(ValueError):
        EngineDeps(repos=h.deps.repos, planner_factory=h.deps.planner_factory,
                   run_control=h.deps.run_control, hook_timeout_s=math.inf)


# ── 3/4. A CancelledError raised by a hook fails closed ──────────────────────


def test_monitor_raising_cancelled_error_fails_closed(factory, metrics):
    h = build(factory, max_turns=4)

    class SelfCancelling:
        async def check(self, turn, context):
            raise asyncio.CancelledError()

    h.deps.monitors = [SelfCancelling()]
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    conv = h.conversations.get(outcome.conversations[0].conversation_id)
    assert conv.status == "stopped_monitor"
    assert len(conv.turns) == 1 and conv.turns[0].monitor_hits == ["monitor_error:SelfCancelling"]
    assert CampaignRepo(factory).get(campaign).status == "completed"
    assert len(h.fake.requests) == 1


def test_run_control_raising_cancelled_error_means_killed(factory):
    h = build(factory, max_turns=4)

    class SelfCancelling:
        async def check(self, campaign_id):
            raise asyncio.CancelledError()

    h.deps.run_control = SelfCancelling()
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "stopped_killed"
    assert h.fake.requests == []


def test_event_sink_raising_cancelled_error_does_not_stop_run(factory):
    h = build(factory, max_turns=2)

    def cancel(event_type, payload):
        raise asyncio.CancelledError()

    h.events.hook = cancel
    outcome = _run(h, new_campaign_id())
    assert outcome.status == "completed" and outcome.conversations[0].turns == 2


# ── 5. A real cancellation during a send is never swallowed ─────────────────


def test_worker_cancel_during_send_propagates_and_stays_resumable(factory):
    fake = FakeTarget(profile="flaky_500", fail_first=1000)
    started = asyncio.Event()

    async def sleep(seconds):
        started.set()
        await asyncio.Event().wait()  # long backoff

    h = build(factory, fake=fake, max_turns=4, sleep=sleep)
    campaign = new_campaign_id()

    async def main():
        task = asyncio.create_task(run_campaign(h.request, campaign, h.deps))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)

    asyncio.run(main())
    from cyberredteam.engine import plan_conversations

    cid = plan_conversations(h.request, campaign)[0].conversation_id
    assert h.conversations.get(cid).status == "running"


# ── 6. Unknown control signals fail closed ───────────────────────────────────


@pytest.mark.parametrize("signal", ["paused", "", 0, "KILLED", object()])
def test_unknown_control_signal_means_killed(factory, signal):
    h = build(factory, max_turns=4)

    class Weird:
        async def check(self, campaign_id):
            return signal

    h.deps.run_control = Weird()
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "stopped_killed"
    assert h.fake.requests == []


# ── 7. Runtime init failure never leaves the campaign "running" ─────────────


def test_ledger_init_failure_leaves_campaign_untouched(factory):
    h = build(factory)
    campaign = new_campaign_id()
    CampaignRepo(factory).create(campaign, h.request.target.target_id, h.request.policy)

    class Broken(BudgetLedgerRepo):
        def totals(self, campaign_id):
            raise RuntimeError("ledger unavailable")

    h.deps.repos.budget = Broken(factory)
    with pytest.raises(RuntimeError):
        _run(h, campaign)
    assert CampaignRepo(factory).get(campaign).status == "queued"
    assert h.fake.requests == []


# ── Optional: planner and monitor timeouts ───────────────────────────────────


def test_hanging_planner_times_out_as_error(factory):
    h = build(factory, max_turns=4)

    class Hangs:
        async def next_turn(self, state):
            if state.turns:
                await asyncio.Event().wait()
            return PlannedTurn(message="hello turn 0")

    h.deps.planner_factory = lambda spec: Hangs()
    h.deps.planner_timeout_s = 0.05
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "error"
    assert len(h.fake.requests) == 1


def test_hanging_monitor_times_out_and_stops(factory):
    h = build(factory, max_turns=4)

    class Hangs:
        async def check(self, turn, context):
            await asyncio.Event().wait()

    h.deps.monitors = [Hangs()]
    h.deps.monitor_timeout_s = 0.05
    outcome = _run(h, new_campaign_id())
    conv = h.conversations.get(outcome.conversations[0].conversation_id)
    assert conv.status == "stopped_monitor" and conv.turns[0].monitor_hits == ["monitor_error:Hangs"]
