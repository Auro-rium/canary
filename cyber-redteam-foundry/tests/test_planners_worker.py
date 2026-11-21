"""WP4 end to end through the WP7 worker path: the planner factory is loaded
from ``settings.planner_factory`` and a benign smoke pack runs through
``execute_campaign`` against FakeTarget (SQLite, and Postgres when configured).
"""

from __future__ import annotations

import asyncio
from collections import Counter

import pytest
from engine_support import build, new_campaign_id

from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.execution import JobRuntime, execute_campaign
from cyberredteam.jobs.runner_wiring import load_planner_factory, make_runner
from cyberredteam.planners import worker as planner_worker
from cyberredteam.settings import get_settings
from cyberredteam.storage.v2.repositories import CampaignRepo, ConversationRepo, SqlTargetStore


@pytest.fixture(autouse=True)
def _fresh_worker_factories():
    planner_worker.scripted.reset()
    planner_worker.llm.reset()
    yield
    planner_worker.scripted.reset()
    planner_worker.llm.reset()


def _runtime(factory, monkeypatch, spec: str, **build_kw):
    monkeypatch.setenv("PLANNER_FACTORY", spec)
    h = build(factory, **build_kw)
    SqlTargetStore(factory).set_verified(h.request.target.target_id, "header")
    cid = new_campaign_id()
    CampaignRepo(factory).create(cid, h.request.target.target_id, h.request.policy)
    rt = JobRuntime(factory=factory, runner=None, control=DbRunControl(factory),
                    heartbeat_interval_s=0.05)
    planner_factory = load_planner_factory(get_settings().planner_factory)
    rt.runner = make_runner(
        rt, planner_factory,
        engine_options={
            "adapter_factory": h.deps.adapter_factory,
            "rate_limiter": h.deps.rate_limiter,
            "clock": h.deps.clock,
        },
    )
    return h, rt, cid


def test_smoke_pack_end_to_end_through_execute_campaign(db_factory, monkeypatch):
    h, rt, cid = _runtime(
        db_factory, monkeypatch, "cyberredteam.planners.worker:scripted",
        techniques=["smoke_greeting", "smoke_context_retention"], max_turns=6,
    )
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    assert CampaignRepo(db_factory).get(cid).status == "completed"

    convs = ConversationRepo(db_factory)
    by_technique = {}
    for conv_id in convs.list_for_campaign(cid):
        conv = convs.get(conv_id, raw=True, actor="test")
        by_technique[conv.technique] = conv
    assert {c.status for c in by_technique.values()} == {"completed"}
    assert [t.message for t in by_technique["smoke_greeting"].turns] == [
        "Hello!", "What is your name?", "Thanks, goodbye."]
    assert [t.message for t in by_technique["smoke_context_retention"].turns] == [
        "Please remember this for later: my favourite colour is teal.",
        "What is my favourite colour?"]
    assert all(t.http_status == 200 for c in by_technique.values() for t in c.turns)
    assert len(h.fake.successful_requests()) == 5

    types = Counter(e.type for e in rt.events.since(cid))
    assert types["campaign_started"] == 1 and types["campaign_complete"] == 1
    assert types["turn"] == 5


def test_llm_worker_entry_fails_closed_without_planner_prompt(db_factory, monkeypatch):
    # prompts/planner.md is owned by the security owner and not shipped: the
    # LLM planner must refuse to run, and nothing may reach the target.
    monkeypatch.delenv("PLANNER_PROMPT_PATH", raising=False)
    h, rt, cid = _runtime(db_factory, monkeypatch, "cyberredteam.planners.worker:llm",
                          techniques=["tech_a"], max_turns=3)
    asyncio.run(execute_campaign(rt, cid))
    convs = ConversationRepo(db_factory)
    statuses = [convs.get(i).status for i in convs.list_for_campaign(cid)]
    assert statuses == ["error"]
    assert h.fake.requests == []


def test_lazy_factory_failure_is_remembered_per_campaign_and_retried_for_the_next(monkeypatch, tmp_path):
    from cyberredteam.engine import ConversationSpec
    from cyberredteam.planners.errors import PlannerFactoryUnavailable

    builds = []

    def failing_make(kind, **kw):
        builds.append(kind)
        from cyberredteam.planners.errors import PlannerPromptMissing
        raise PlannerPromptMissing("missing")

    monkeypatch.setattr(planner_worker, "make_planner_factory", failing_make)
    lazy = planner_worker._LazyPlannerFactory("llm")
    a = [ConversationSpec(campaign_id="camp-a", technique="t", trial_index=i) for i in range(3)]
    with pytest.raises(PlannerFactoryUnavailable) as first:
        lazy(a[0])
    for spec in a[1:]:
        with pytest.raises(PlannerFactoryUnavailable) as again:
            lazy(spec)
        assert again.value is first.value  # the same failure, not rebuilt per conversation
    assert builds == ["llm"]
    with pytest.raises(PlannerFactoryUnavailable):
        lazy(ConversationSpec(campaign_id="camp-b", technique="t", trial_index=0))
    assert builds == ["llm", "llm"]  # a new campaign retries the build


def test_lazy_factory_memoizes_any_build_failure_not_only_config_errors(monkeypatch):
    from cyberredteam.engine import ConversationSpec
    from cyberredteam.planners.errors import PlannerFactoryUnavailable

    builds = []

    def failing_make(kind, **kw):
        builds.append(kind)
        raise RuntimeError("BACKBOARD_API_KEY is not configured")  # e.g. the LLM factory

    monkeypatch.setattr(planner_worker, "make_planner_factory", failing_make)
    lazy = planner_worker._LazyPlannerFactory("llm")
    specs = [ConversationSpec(campaign_id="camp-a", technique="t", trial_index=i) for i in range(3)]
    for spec in specs:
        with pytest.raises(PlannerFactoryUnavailable) as err:
            lazy(spec)
    assert builds == ["llm"]
    assert "RuntimeError" in str(err.value) and "BACKBOARD" not in str(err.value)  # class name only
