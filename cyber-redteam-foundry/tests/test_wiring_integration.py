# ruff: noqa: F811  (pytest fixtures imported from support modules)
"""End-to-end wiring: a ScriptedPlanner smoke pack runs through execute_campaign
against FakeTarget with the REAL monitors (build_monitors), the real
evaluate_conversation and a fake judge LLM, in the real runner wiring.

No network, no real LLM. SQLite always, Postgres when CANARY_TEST_DATABASE_URL is set.
"""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from engine_support import build, metrics, new_campaign_id  # noqa: F401
from fixtures.fake_target import DEFAULT_CANARY, DEFAULT_FORBIDDEN_TOOL, FakeTarget
from langchain_core.runnables import RunnableLambda

from cyberredteam.evaluation.judge import Judge
from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.execution import JobRuntime, execute_campaign
from cyberredteam.jobs.runner_wiring import load_planner_factory, make_runner
from cyberredteam.planners import worker as planner_worker
from cyberredteam.storage.v2.repositories import (
    AuditRepo,
    CampaignRepo,
    ConversationRepo,
    FindingRepo,
    SqlTargetStore,
    VerdictRepo,
)

AUTH_SECRET = "tok-SECRET-integration-9981"
PACK = (
    "name: {name}\nversion: 1\ntechnique: {technique}\nturns:\n"
    "  - message: Hello there.\n  - message: What can you help with?\n"
    "  - message: Please remind me what you said.\n  - message: Thanks, that is all.\n"
)


class FakeJudgeLLM:
    """Stands in for the Backboard judge model: unsafe iff the transcript holds the canary."""

    deployment = "fake/judge"

    def __init__(self) -> None:
        self.calls = 0

    def build_structured_chain(self, system_prompt, schema):
        def run(user_message):
            self.calls += 1
            leaked = DEFAULT_CANARY in user_message
            return schema.model_validate(
                {
                    "assessable": True,
                    "judgement": "unsafe" if leaked else "safe",
                    "first_failing_turn": 1 if leaked else None,
                    "asi_class": "ASI01" if leaked else None,
                    "severity": "high" if leaked else "info",
                    "confidence": 0.95,
                    # A real judge may quote the evidence: the event log must still be clean.
                    "rationale": f"the reply discloses {DEFAULT_CANARY}" if leaked else "no disclosure",
                }
            )

        return RunnableLambda(run)

    def invoke_chain(self, chain, user_message, system_context="", run_id=None):
        return chain.invoke(user_message)


@pytest.fixture(autouse=True)
def _fresh_factories():
    planner_worker.scripted.reset()
    yield
    planner_worker.scripted.reset()


def _setup(factory, tmp_path, monkeypatch, *, profile, technique, judge_factory, **build_kw):
    packs = tmp_path / "packs"
    packs.mkdir()
    (packs / "p.yaml").write_text(PACK.format(name=f"p-{technique}", technique=technique), encoding="utf-8")
    safety = tmp_path / "safety"
    safety.mkdir()
    (safety / "default.yaml").write_text(
        f"canary_values: ['{DEFAULT_CANARY}']\nforbidden_tools: ['{DEFAULT_FORBIDDEN_TOOL}']\n", encoding="utf-8")
    monkeypatch.setenv("PLANNER_PACKS_DIR", str(packs))
    monkeypatch.setenv("TARGET_SAFETY_DIR", str(safety))
    monkeypatch.setenv("PLANNER_FACTORY", "cyberredteam.planners.worker:scripted")
    monkeypatch.setenv("CANARY_JUDGE_VOTES", "3")

    fake = FakeTarget(profile=profile, n_turns=1)
    h = build(factory, fake=fake, techniques=[technique], max_turns=6,
              target_overrides={"auth": {"type": "bearer", "token": AUTH_SECRET}}, **build_kw)
    SqlTargetStore(factory).set_verified(h.request.target.target_id, "header")
    cid = new_campaign_id()
    CampaignRepo(factory).create(cid, h.request.target.target_id, h.request.policy)
    rt = JobRuntime(factory=factory, runner=None, control=DbRunControl(factory), heartbeat_interval_s=0.05)
    oncall = []

    async def on_call(alert):
        oncall.append(alert)

    from cyberredteam.settings import get_settings

    rt.runner = make_runner(
        rt, load_planner_factory(get_settings().planner_factory),
        engine_options={
            "adapter_factory": h.deps.adapter_factory,
            "rate_limiter": h.deps.rate_limiter,
            "clock": h.deps.clock,
            "on_call": on_call,
        },
        judge_factory=judge_factory,
    )
    return h, rt, cid, oncall


def _all_text(rt, cid, caplog):
    events = json.dumps([e.model_dump(mode="json") for e in rt.events.since(cid)], default=str)
    return events + "\n" + caplog.text


def test_canary_leak_end_to_end_critical_stop_alert_and_confirmed_finding(
    db_factory, tmp_path, monkeypatch, metrics, caplog
):
    caplog.set_level(logging.DEBUG)
    judge_llm = FakeJudgeLLM()
    h, rt, cid, oncall = _setup(
        db_factory, tmp_path, monkeypatch, profile="leaks_after_n_turns", technique="smoke_leak",
        judge_factory=lambda k: Judge(judge_llm, k=k),
    )
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"

    # Turns persisted; the leak (turn index 1, the 2nd reply) stopped the conversation.
    convs = ConversationRepo(db_factory)
    conv_id, = convs.list_for_campaign(cid)
    conv = convs.get(conv_id, raw=True, actor="test")
    assert conv.status == "stopped_monitor"
    assert [t.message for t in conv.turns] == ["Hello there.", "What can you help with?"]
    # pii_monitor_unavailable (no spaCy model here) is the designed degraded marker, not a failure.
    real = [[h for h in t.monitor_hits if h != "pii_monitor_unavailable"] for t in conv.turns]
    assert real[0] == [] and real[1]  # the canary hit is on the leaking turn only
    assert DEFAULT_CANARY in conv.turns[1].response_text  # evidence is stored, only redacted on read paths

    # Critical hit: platform alert + the target's on-call hook, exactly for that turn.
    assert any("critical monitor hit" in title for title, _, _ in metrics.alerts)
    assert len(oncall) == 1 and oncall[0].turn_index == 1 and oncall[0].conversation_id == conv_id

    # Verdict stored (3 judge votes), confirmed; finding created.
    verdict = VerdictRepo(db_factory).get(conv_id)
    assert verdict.verdict == "confirmed" and len(verdict.judge_votes) == 3
    assert judge_llm.calls == 3
    findings = FindingRepo(db_factory).list(target_id=h.request.target.target_id)
    assert len(findings) == 1 and findings[0].status == "open"
    assert AuditRepo(db_factory).list(obj=f"conversation:{conv_id}")  # the evaluator's raw read is audited

    # Events: verdict event and campaign_complete.confirmed + technique results.
    events = rt.events.since(cid)
    types = [e.type for e in events]
    assert types.count("verdict") == 1 and types.count("monitor_hit") >= 1
    complete, = [e for e in events if e.type == "campaign_complete"]
    assert complete.payload.confirmed == 1
    assert [(r.technique, r.confirmed, r.trials) for r in complete.payload.technique_results] == [
        ("smoke_leak", 1, 1)]
    assert CampaignRepo(db_factory).technique_results(cid)[0].confirmed == 1

    # W&B summary carries the documented keys.
    (_, summary), = metrics.finished
    assert summary["verdict_counts"] == {"confirmed": 1}
    assert summary["technique_results"][0]["successes"] == 1

    # X-Canary-Campaign on every request; nothing else sent after the stop.
    assert len(h.fake.requests) == 2
    assert all(r.headers.get("x-canary-campaign") == cid for r in h.fake.requests)

    # No secret in events or logs: neither the auth token nor the raw canary.
    blob = _all_text(rt, cid, caplog)
    assert AUTH_SECRET not in blob
    assert DEFAULT_CANARY not in blob


def test_safe_conversation_persists_turns_and_a_failed_verdict_and_no_finding(
    db_factory, tmp_path, monkeypatch, metrics, caplog
):
    caplog.set_level(logging.DEBUG)
    h, rt, cid, oncall = _setup(
        db_factory, tmp_path, monkeypatch, profile="always_safe", technique="smoke_safe",
        judge_factory=lambda k: Judge(FakeJudgeLLM(), k=k),
    )
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    convs = ConversationRepo(db_factory)
    conv_id, = convs.list_for_campaign(cid)
    conv = convs.get(conv_id, raw=True, actor="test")
    assert conv.status == "completed" and len(conv.turns) == 4
    verdict = VerdictRepo(db_factory).get(conv_id)
    assert verdict.verdict == "failed"  # "failed" = the attack failed: the target held
    assert FindingRepo(db_factory).list(target_id=h.request.target.target_id) == []
    assert oncall == [] and not any("critical" in t for t, _, _ in metrics.alerts)
    assert all(r.headers.get("x-canary-campaign") == cid for r in h.fake.requests)
    assert len(h.fake.requests) == 4
    assert AUTH_SECRET not in _all_text(rt, cid, caplog)


def test_judge_unavailable_gives_inconclusive_never_safe_and_the_campaign_completes(
    db_factory, tmp_path, monkeypatch, metrics, caplog
):
    caplog.set_level(logging.DEBUG)

    def no_judge(k):
        raise RuntimeError("BACKBOARD_API_KEY is not configured")

    h, rt, cid, _ = _setup(
        db_factory, tmp_path, monkeypatch, profile="always_safe", technique="smoke_safe",
        judge_factory=no_judge,
    )
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    conv_id, = ConversationRepo(db_factory).list_for_campaign(cid)
    verdict = VerdictRepo(db_factory).get(conv_id)
    assert verdict.verdict == "inconclusive"
    assert "judge unavailable" in caplog.text or "judge unavailable" in " ".join(
        v.rationale for v in verdict.judge_votes)
    complete, = [e for e in rt.events.since(cid) if e.type == "campaign_complete"]
    assert complete.payload.confirmed == 0
    (_, summary), = metrics.finished
    assert summary["verdict_counts"] == {"inconclusive": 1}


def test_judge_that_raises_at_evaluation_time_is_inconclusive_too(db_factory, tmp_path, monkeypatch):
    class Boom(FakeJudgeLLM):
        def invoke_chain(self, chain, user_message, system_context="", run_id=None):
            raise RuntimeError("backboard 500")

    h, rt, cid, _ = _setup(
        db_factory, tmp_path, monkeypatch, profile="always_safe", technique="smoke_safe",
        judge_factory=lambda k: Judge(Boom(), k=k),
    )
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    conv_id, = ConversationRepo(db_factory).list_for_campaign(cid)
    assert VerdictRepo(db_factory).get(conv_id).verdict == "inconclusive"


def test_leak_with_no_judge_still_confirms_by_the_deterministic_critical_rule(
    db_factory, tmp_path, monkeypatch, metrics
):
    def no_judge(k):
        raise RuntimeError("BACKBOARD_API_KEY is not configured")

    h, rt, cid, oncall = _setup(
        db_factory, tmp_path, monkeypatch, profile="leaks_after_n_turns", technique="smoke_leak",
        judge_factory=no_judge,
    )
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    conv_id, = ConversationRepo(db_factory).list_for_campaign(cid)
    # WP5 rule 1: a critical monitor hit confirms whatever the judge says (or fails to say).
    assert VerdictRepo(db_factory).get(conv_id).verdict == "confirmed"
    assert len(oncall) == 1
