# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""WP3 round-3 regressions: the engine boundary normalises forged requests,
budget caps fail closed, self-raised CancelledError never leaves rows running,
signals are literal, malformed monitor results keep the turn, and a worker
cancellation delivered while the send watcher is being awaited propagates."""

from __future__ import annotations

import asyncio

import pytest
from engine_support import _key, build, factory, new_campaign_id  # noqa: F401
from fixtures.fake_target import FakeTarget
from pydantic import ValidationError

from cyberredteam.contracts import CampaignPolicy, CampaignRequest, TargetConfig
from cyberredteam.engine import (
    BudgetLedger,
    CampaignRefused,
    MonitorHit,
    MonitorResult,
    PlannedTurn,
    plan_conversations,
    run_campaign,
)
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo, CampaignRepo


def _run(h, campaign_id, request=None):
    return asyncio.run(run_campaign(request or h.request, campaign_id, h.deps))


def _forged(h, *, target=None, policy=None, **policy_overrides):
    t = h.request.target
    tgt = TargetConfig.model_construct(**{**dict(t), **(target or {})})
    if policy is None:
        policy = CampaignPolicy.model_construct(**{**dict(h.request.policy), **policy_overrides})
    return CampaignRequest.model_construct(target=tgt, policy=policy)


def _refused(h, request):
    campaign = new_campaign_id()
    with pytest.raises(CampaignRefused):
        _run(h, campaign, request)
    assert CampaignRepo(h.factory).get(campaign) is None
    assert h.fake.requests == []


class AlwaysEqualStr(str):
    def __eq__(self, other):
        return True

    __hash__ = str.__hash__


class LooksSmallInt(int):
    def __le__(self, other):
        return True

    def __lt__(self, other):
        return True

    def __gt__(self, other):
        return False

    def __ge__(self, other):
        return False


class LooksSmallFloat(float):
    def __le__(self, other):
        return True

    def __gt__(self, other):
        return False


# ── Normalisation at the boundary ────────────────────────────────────────────


def test_str_subclass_posing_as_staging_gets_production_rules(factory):
    h = build(factory, max_total_requests=100, max_parallel_conversations=2)
    _refused(h, _forged(h, target={"environment": AlwaysEqualStr("production")},
                        max_parallel_conversations=10))


def test_numeric_subclasses_with_lying_comparisons_refused(factory):
    h = build(factory, target_overrides={"environment": "production"},
              max_total_requests=100, max_parallel_conversations=2)
    _refused(h, _forged(h, max_parallel_conversations=LooksSmallInt(50)))
    _refused(h, _forged(h, max_total_requests=LooksSmallInt(5000)))
    _refused(h, _forged(h, rate_limit_rps=LooksSmallFloat(50.0)))


def test_huge_integer_rejected_on_validated_and_forged_paths(factory):
    with pytest.raises(ValidationError):
        CampaignPolicy(techniques=["a"], max_total_requests=10**400)
    with pytest.raises(ValidationError):
        CampaignPolicy(techniques=["a"], max_total_requests=1_000_001)
    with pytest.raises(ValidationError):
        CampaignPolicy(techniques=["a"], max_llm_cost_usd=10_001)
    h = build(factory)
    _refused(h, _forged(h, max_total_requests=10**400))
    _refused(h, _forged(h, max_parallel_conversations=10**400))


def test_ledger_cap_set_to_huge_after_validation_counts_as_exhausted(factory):
    policy = CampaignPolicy(techniques=["a"])
    policy.max_total_requests = 10**400  # no validate_assignment: bypasses the bound
    ledger = BudgetLedger("c-huge", policy, BudgetLedgerRepo(factory))
    assert ledger.exhausted()
    assert asyncio.run(ledger.charge_request()) is False
    assert ledger.remaining_pct() == 0.0


def test_none_dict_and_incomplete_policies_refused(factory):
    h = build(factory)
    _refused(h, CampaignRequest.model_construct(target=h.request.target, policy=None))
    _refused(h, CampaignRequest.model_construct(
        target=h.request.target, policy=h.request.policy.model_dump()))
    incomplete = CampaignPolicy.model_construct(**dict(h.request.policy))
    del incomplete.__dict__["max_turns"]
    _refused(h, _forged(h, policy=incomplete))
    _refused(h, CampaignRequest.model_construct(policy=h.request.policy))  # no target


def test_forged_truthy_values_are_not_coerced(factory):
    h = build(factory)
    _refused(h, _forged(h, allow_destructive_tools="no"))
    _refused(h, _forged(h, trials_per_technique=True))
    _refused(h, _forged(h, target={"verified": "true"}))


def test_engine_uses_the_normalised_copy(factory):
    class PlainSubclass(int):
        pass

    h = build(factory, max_turns=2)
    forged = _forged(h, max_turns=PlainSubclass(2), techniques=["a "])
    from cyberredteam.engine.runner import normalize_request

    normalized = normalize_request(forged)
    assert type(normalized.policy.max_turns) is int
    assert normalized is not forged
    outcome = _run(h, new_campaign_id(), forged)
    assert outcome.conversations[0].turns == 2


def test_auth_secrets_survive_normalisation(factory):
    seen = []
    import httpx

    def handler(request):
        seen.append((request.url.path, request.headers.get("authorization")))
        return httpx.Response(200, json={"reply": "ok"})

    h = build(factory, max_turns=1, target_overrides={"auth": {"type": "bearer", "token": "s3cret-tok"}})
    h.transport = httpx.MockTransport(handler)
    _run(h, new_campaign_id())
    assert seen == [("/chat", "Bearer s3cret-tok")]


# ── Technique normalisation ──────────────────────────────────────────────────


def test_workflow_manipulation_variants_are_staging_only(factory):
    with pytest.raises(ValidationError):
        CampaignPolicy(techniques=["workflow_manipulation", "Workflow_Manipulation "])
    pol = CampaignPolicy(techniques=["Workflow_Manipulation "])
    assert any("staging-only" in p for p in pol.production_violations())
    h = build(factory, target_overrides={"environment": "production"},
              max_total_requests=100, max_parallel_conversations=2)
    with pytest.raises(ValidationError):
        CampaignRequest(target=h.request.target, policy=pol.model_copy(update={
            "max_total_requests": 100, "max_parallel_conversations": 2}))
    _refused(h, _forged(h, techniques=["Workflow_Manipulation "]))


# ── Self-raised CancelledError never leaves rows running ────────────────────


def test_planner_raising_cancelled_error_ends_as_error(factory):
    h = build(factory, max_turns=4)

    class Cancels:
        async def next_turn(self, state):
            if state.turns:
                raise asyncio.CancelledError()
            return PlannedTurn(message="hello turn 0")

    h.deps.planner_factory = lambda spec: Cancels()
    campaign = new_campaign_id()
    outcome = _run(h, campaign)
    assert outcome.conversations[0].status == "error"
    assert h.conversations.get(outcome.conversations[0].conversation_id).status == "error"
    assert CampaignRepo(factory).get(campaign).status == "completed"


def test_planner_factory_raising_cancelled_error_ends_as_error(factory):
    h = build(factory)

    def boom(spec):
        raise asyncio.CancelledError()

    h.deps.planner_factory = boom
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "error"
    assert h.fake.requests == []


# ── Control signals are literal ──────────────────────────────────────────────


@pytest.mark.parametrize("signal", [AlwaysEqualStr("cancelled"), AlwaysEqualStr("x")])
def test_signal_with_always_true_eq_means_killed(factory, signal):
    h = build(factory, max_turns=4)

    class Weird:
        async def check(self, campaign_id):
            return signal

    h.deps.run_control = Weird()
    outcome = _run(h, new_campaign_id())
    assert outcome.conversations[0].status == "stopped_killed"
    assert h.fake.requests == []


# ── Malformed monitor results keep the turn ──────────────────────────────────


def _without(model, field):
    del model.__dict__[field]
    return model


@pytest.mark.parametrize("bad", [
    lambda: MonitorResult.model_construct(hits=[], stop="yes", critical=False),
    lambda: MonitorResult.model_construct(hits=[], stop=False, critical=None),
    lambda: MonitorResult.model_construct(hits=["not-a-hit"], stop=False, critical=False),
    lambda: MonitorResult.model_construct(
        hits=[MonitorHit.model_construct(name="x", severity="apocalyptic")], stop=False, critical=False),
    lambda: _without(MonitorResult.model_construct(stop=False, critical=False), "hits"),
    lambda: MonitorResult.model_construct(hits=None, stop=False, critical=False),
])
def test_malformed_monitor_result_is_monitor_error_and_turn_kept(factory, bad):
    h = build(factory, max_turns=4)

    class Malformed:
        async def check(self, turn, context):
            return bad()

    h.deps.monitors = [Malformed()]
    outcome = _run(h, new_campaign_id())
    conv = h.conversations.get(outcome.conversations[0].conversation_id)
    assert conv.status == "stopped_monitor"
    assert len(conv.turns) == 1 and conv.turns[0].monitor_hits == ["monitor_error:Malformed"]
    assert len(h.fake.requests) == 1


# ── Worker cancellation while the send watcher is awaited ────────────────────


def test_cancel_while_awaiting_watcher_cleanup_propagates(factory):
    """The send finishes, the finally block cancels the RunControl watcher and
    awaits it; the watcher's check does slow cleanup when cancelled. The worker
    cancellation arrives during that await. It must propagate (no more turns);
    the old ``contextlib.suppress(CancelledError)`` swallowed it and the
    conversation kept sending."""
    fake = FakeTarget(profile="slow", delay_s=0.3)
    h = build(factory, fake=fake, max_turns=3)
    h.transport = fake.async_transport()
    cleanup_started = asyncio.Event()

    class SlowInWatcher:
        async def check(self, campaign_id):
            task = asyncio.current_task()
            if task is None or "watch" not in task.get_coro().__qualname__:
                return None
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleanup_started.set()
                await asyncio.sleep(0.5)  # slow cleanup
                raise

    h.deps.run_control = SlowInWatcher()
    h.deps.control_poll_s = 0.05
    h.deps.hook_timeout_s = 30
    campaign = new_campaign_id()

    async def main():
        task = asyncio.create_task(run_campaign(h.request, campaign, h.deps))
        await cleanup_started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 10)

    asyncio.run(main())
    assert len(fake.requests) == 1
    cid = plan_conversations(h.request, campaign)[0].conversation_id
    assert h.conversations.get(cid).status == "running"
