# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""Lead wiring (engine side): evaluation hooks, planner guard-rail status and
budget, campaign-fatal planner config, WP3/WP4 review follow-ups."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass

import pytest
from fixtures.fake_target import FakeTarget
from engine_support import (  # noqa: F401
    ScriptedPlanner,
    _key,
    build,
    factory,
    metrics,
    new_campaign_id,
)
from pydantic import ValidationError

from cyberredteam.contracts import ConversationVerdict, JudgeVote, TechniqueResult
from cyberredteam.engine import CampaignRefused, ConversationState, PlannedTurn, run_campaign
from cyberredteam.engine.runner import normalize_request
from cyberredteam.engine.types import CampaignAggregate
from cyberredteam.planners import PlannerRefused
from cyberredteam.planners.errors import PackError, PlannerFactoryUnavailable
from cyberredteam.settings import Settings


def _run(h, cid=None):
    return asyncio.run(run_campaign(h.request, cid or new_campaign_id(), h.deps))


def _verdict(cid, verdict="inconclusive"):
    return ConversationVerdict(
        conversation_id=cid, verdict=verdict, judge_agreement=1.0, severity="info", asi_class="ASI01",
        rationale="test",
    )


# ── evaluation hooks ─────────────────────────────────────────────────────────


def test_evaluator_runs_per_conversation_emits_verdict_and_confirmed_count(factory):
    h = build(factory, techniques=["technique_a", "technique_b"], max_turns=2)
    seen = []

    async def evaluator(cid):
        seen.append(cid)
        return _verdict(cid, "confirmed")

    def aggregate(campaign_id):
        return CampaignAggregate(
            technique_results=[TechniqueResult.from_counts("technique_a", 1, 1),
                               TechniqueResult.from_counts("technique_b", 1, 1)],
            verdict_counts={"confirmed": 2},
        )

    h.deps.evaluator = evaluator
    h.deps.aggregate_results = aggregate
    outcome = _run(h)
    assert sorted(seen) == sorted(c.conversation_id for c in outcome.conversations)
    assert len(h.events.of_type("verdict")) == 2
    complete, = h.events.of_type("campaign_complete")
    assert complete.confirmed == 2 and len(complete.technique_results) == 2


def test_campaign_finished_metrics_carry_documented_summary_keys(factory, metrics):
    h = build(factory, max_turns=2)
    h.deps.aggregate_results = lambda cid: CampaignAggregate(
        technique_results=[TechniqueResult.from_counts("technique_a", 4, 1)],
        verdict_counts={"confirmed": 1, "failed": 3},
    )
    _run(h)
    (_, summary), = metrics.finished
    assert summary["verdict_counts"] == {"confirmed": 1, "failed": 3}
    row, = summary["technique_results"]
    assert {"technique", "success_rate", "ci_low", "ci_high", "trials", "successes"} <= set(row)
    assert summary["headline"]["confirmed"] == 1


def test_stop_on_first_confirmed_skips_unstarted_conversations(factory):
    h = build(factory, techniques=["technique_a"], trials_per_technique=4, max_turns=2,
              max_parallel_conversations=1, stop_on_first_confirmed=True)

    async def evaluator(cid):
        return _verdict(cid, "confirmed")

    h.deps.evaluator = evaluator
    outcome = _run(h)
    assert len(outcome.conversations) == 1  # the other three were never started
    assert outcome.status == "completed"


def test_without_stop_on_first_confirmed_every_conversation_runs(factory):
    h = build(factory, techniques=["technique_a"], trials_per_technique=3, max_turns=2,
              max_parallel_conversations=1)

    async def evaluator(cid):
        return _verdict(cid, "confirmed")

    h.deps.evaluator = evaluator
    assert len(_run(h).conversations) == 3


def test_evaluator_failure_never_crashes_the_campaign_or_emits_a_verdict(factory):
    h = build(factory, max_turns=2)

    async def evaluator(cid):
        raise RuntimeError("backboard down")

    h.deps.evaluator = evaluator
    outcome = _run(h)
    assert outcome.status == "completed"
    assert h.events.of_type("verdict") == []  # absence of a verdict is never "safe"


def test_evaluator_that_cancels_itself_does_not_crash_the_campaign(factory):
    h = build(factory, max_turns=2)

    async def evaluator(cid):
        raise asyncio.CancelledError()

    h.deps.evaluator = evaluator
    assert _run(h).status == "completed"


def test_killed_conversations_are_not_judged(factory):
    h = build(factory, max_turns=3)
    called = []

    async def kill_after_first_turn(event_type, payload):
        if event_type == "turn":
            await h.control.kill_all()

    h.events.hook = kill_after_first_turn

    async def evaluator(cid):
        called.append(cid)
        return _verdict(cid)

    h.deps.evaluator = evaluator
    outcome = _run(h)
    assert outcome.status == "killed" and called == []


def test_resumed_campaign_asks_the_evaluator_about_terminal_conversations_again(factory):
    h = build(factory, max_turns=2)
    cid = new_campaign_id()
    calls = []

    async def evaluator(conv_id):
        calls.append(conv_id)
        return None  # "already evaluated"

    h.deps.evaluator = evaluator
    asyncio.run(run_campaign(h.request, cid, h.deps))
    asyncio.run(run_campaign(h.request, cid, h.deps))
    assert len(calls) == 2 and calls[0] == calls[1]
    assert h.events.of_type("verdict") == []


# ── WP4 follow-ups: planner guard rail status, budget, campaign-fatal config ─


class _RefusingPlanner:
    def __init__(self, tokens, usd):
        self.tokens, self.usd = tokens, usd

    async def next_turn(self, state: ConversationState):
        raise PlannerRefused("structural", llm_tokens=self.tokens, llm_cost_usd=self.usd)


def test_planner_guardrail_stop_gets_its_own_status_and_is_charged(factory):
    h = build(factory, max_turns=3, max_llm_cost_usd=5.0)
    h.deps.planner_factory = lambda spec: _RefusingPlanner(1200, 0.25)
    outcome = _run(h)
    conv, = outcome.conversations
    assert conv.status == "stopped_planner_guardrail"
    assert outcome.llm_cost_usd == pytest.approx(0.25)
    assert h.fake.requests == []
    stored = h.conversations.get(conv.conversation_id)
    assert stored.status == "stopped_planner_guardrail"


@pytest.mark.parametrize("bad", [math.nan, math.inf, -1.0])
def test_non_finite_or_negative_planner_cost_exhausts_the_budget(factory, bad):
    class Planner(ScriptedPlanner):
        async def next_turn(self, state):
            await asyncio.sleep(0)
            return PlannedTurn.model_construct(  # bypass validation: a buggy planner
                message="hello", intent_note="", end_conversation=False, llm_tokens=0, llm_cost_usd=bad,
            )

    h = build(factory, max_turns=5)
    h.deps.planner_factory = lambda spec: Planner()
    outcome = _run(h)
    assert outcome.conversations[0].status == "stopped_budget"
    assert len(h.fake.requests) <= 1  # the cost is never skipped silently; nothing runs on


def test_planner_factory_config_error_fails_the_campaign_once(factory):
    h = build(factory, techniques=["technique_a", "technique_b"], max_turns=2,
              max_parallel_conversations=2)
    calls = []

    def planner_factory(spec):
        calls.append(spec.conversation_id)
        raise PlannerFactoryUnavailable("planner factory unavailable")

    h.deps.planner_factory = planner_factory
    cid = new_campaign_id()
    with pytest.raises(BaseException):  # noqa: B017  (ExceptionGroup from the TaskGroup)
        asyncio.run(run_campaign(h.request, cid, h.deps))
    assert h.deps.repos.campaigns.get(cid).status == "failed"
    assert [e for e in h.events.of_type("campaign_failed")] and len(h.events.of_type("campaign_failed")) == 1
    assert h.fake.requests == []


def test_planner_config_error_that_is_not_campaign_fatal_stays_per_conversation(factory):
    h = build(factory, techniques=["technique_a", "technique_b"], max_turns=2)

    def planner_factory(spec):
        if spec.technique == "technique_a":
            raise PackError("no pack for this technique")
        return ScriptedPlanner()

    h.deps.planner_factory = planner_factory
    outcome = _run(h)
    assert sorted(c.status for c in outcome.conversations) == ["completed", "error"]


# ── WP3 follow-ups ───────────────────────────────────────────────────────────


def test_self_raised_cancelled_error_outside_run_conversation_try_fails_the_campaign(factory):
    h = build(factory, max_turns=2)
    original = h.deps.repos.conversations.create

    def create(conv):
        raise asyncio.CancelledError()  # not a real cancel of the campaign task

    h.deps.repos.conversations.create = create  # type: ignore[method-assign]
    cid = new_campaign_id()
    with pytest.raises(RuntimeError):
        asyncio.run(run_campaign(h.request, cid, h.deps))
    h.deps.repos.conversations.create = original  # type: ignore[method-assign]
    assert h.deps.repos.campaigns.get(cid).status == "failed"  # never left "running"
    assert len(h.events.of_type("campaign_failed")) == 1


def test_normalize_request_requires_exactly_campaign_request(factory):
    h = build(factory)

    class Sub(type(h.request)):
        pass

    sub = Sub.model_construct(**{k: getattr(h.request, k) for k in type(h.request).model_fields})
    with pytest.raises(CampaignRefused):
        normalize_request(sub)
    assert normalize_request(h.request).target.target_id == h.request.target.target_id


# ── settings validators ──────────────────────────────────────────────────────


@pytest.mark.parametrize("field,value", [
    ("planner_transcript_chars_per_turn", 0),
    ("planner_max_message_chars", 0),
    ("planner_max_message_chars", -5),
    ("planner_usd_per_1k_input_tokens", 0),
    ("planner_usd_per_1k_output_tokens", -0.01),
])
def test_planner_settings_reject_non_positive_values(field, value):
    with pytest.raises(ValidationError):
        Settings(**{field: value})
    Settings()  # defaults are fine


OPAQUE_AUTH = "zq7-UNIQUE-hdr-value-4f9c1"  # matches no redaction pattern on purpose


@dataclass
class _EchoAuthTarget(FakeTarget):
    def _reply(self, turn: int) -> str:
        return f"your key is {OPAQUE_AUTH} (turn {turn})"


def test_verdict_rationale_and_turn_previews_mask_the_targets_own_auth_secret(factory):
    h = build(factory, max_turns=2, fake=_EchoAuthTarget(),
              target_overrides={"auth": {"type": "bearer", "token": OPAQUE_AUTH}})

    async def evaluator(cid):
        return ConversationVerdict(
            conversation_id=cid, verdict="inconclusive", judge_agreement=1.0, severity="info",
            asi_class="ASI01", rationale=f"the reply quotes {OPAQUE_AUTH}",
            judge_votes=[JudgeVote(vote_index=0, judgement="inconclusive", confidence=0.5,
                                   rationale=f"saw {OPAQUE_AUTH} in turn 0")],
        )

    h.deps.evaluator = evaluator
    _run(h)
    verdict_events = h.events.of_type("verdict")
    assert verdict_events
    for ev in verdict_events:
        blob = ev.model_dump_json()
        assert OPAQUE_AUTH not in blob and "REDACTED" in blob
    turn_events = h.events.of_type("turn")
    assert turn_events
    assert all(OPAQUE_AUTH not in ev.model_dump_json() for ev in turn_events)
