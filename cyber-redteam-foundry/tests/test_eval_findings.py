"""B7/B9 findings and the evaluate_conversation pipeline, on SQLite and Postgres."""

from __future__ import annotations

import asyncio

import pytest
from cryptography.fernet import Fernet
from eval_support import FakeJudgeLLM, conversation, fixed, out
from storage_v2_support import make_policy, make_target, migrate_down, migrate_up, pg_url

from cyberredteam.contracts import ConversationVerdict, ToolCallObservation
from cyberredteam.evaluation.findings import (
    DEDUP_MERGED_ACTION,
    finding_id,
    mark_distinct,
    resolve_component,
    upsert_finding_for_verdict,
)
from cyberredteam.evaluation.judge import Judge
from cyberredteam.evaluation.pipeline import (
    EvaluationDeps,
    compute_technique_results,
    evaluate_conversation,
)
from cyberredteam.evaluation.verdict import EvaluationSettings
from cyberredteam.storage.v2.db import make_engine, make_session_factory
from cyberredteam.storage.v2.encrypted import reset_key_cache
from cyberredteam.storage.v2.repositories import (
    AuditRepo,
    CampaignRepo,
    ConversationRepo,
    FindingRepo,
    SqlTargetStore,
    VerdictRepo,
)

BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(
    not pg_url(), reason="CANARY_TEST_DATABASE_URL not set"))]
DIM = 384


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    reset_key_cache()
    yield
    reset_key_cache()


@pytest.fixture(params=BACKENDS)
def factory(request, tmp_path):
    url = pg_url() if request.param == "postgres" else f"sqlite:///{tmp_path / 'v2.db'}"
    if request.param == "postgres":
        migrate_down(url)
    migrate_up(url)
    engine = make_engine(url)
    yield make_session_factory(engine)
    engine.dispose()
    if request.param == "postgres":
        migrate_down(url)


@pytest.fixture
def env(factory):
    target = make_target()
    SqlTargetStore(factory).create(target)
    CampaignRepo(factory).create("camp-1", target.target_id, make_policy(), created_by="op")
    return {
        "target_id": target.target_id,
        "findings": FindingRepo(factory),
        "audit": AuditRepo(factory),
        "verdicts": VerdictRepo(factory),
        "conversations": ConversationRepo(factory),
        "campaigns": CampaignRepo(factory),
    }


def _verdict(conv, verdict="confirmed", first=0, severity="high", hits=()):
    return ConversationVerdict(
        conversation_id=conv.conversation_id, verdict=verdict, first_failing_turn=first,
        deterministic_hits=list(hits), judge_agreement=1.0, severity=severity, asi_class="ASI02",
    )


def mk(env, *a, **kw):
    """A conversation stored in the DB (findings reference it)."""
    kw.setdefault("campaign_id", "camp-1")
    conv = conversation(*a, **kw)
    env["conversations"].create(conv)
    return conv


def _vec(*head: float) -> list[float]:
    v = list(head) + [0.0] * (DIM - len(head))
    return v


# ── identity (B7) ────────────────────────────────────────────────────────────


def test_component_is_the_real_tool_and_part_of_the_id():
    tools = [[ToolCallObservation(name="lookup_order_status"), ToolCallObservation(name="delete_record")]]
    conv = conversation(["ok"], tools=tools, technique="tool_misuse")
    v = _verdict(conv)
    assert resolve_component(conv, v, {"delete_record"}) == "tool:delete_record"
    assert resolve_component(conv, v) == "tool:lookup_order_status"
    assert resolve_component(conversation(["leak"]), v) == "reply"
    heuristic = conversation(["x"], tools=[[ToolCallObservation(name="t", source="heuristic")]])
    assert resolve_component(heuristic, v) == "reply"
    a = finding_id("t1", "tool:delete_record", "tool_misuse", "ASI02")
    b = finding_id("t1", "tool:lookup_order_status", "tool_misuse", "ASI02")
    assert a != b and len(a) == 16


def test_confirmed_opens_finding_with_component(env):
    conv = mk(env, ["ok"], tools=[["delete_record"]], technique="tool_misuse")
    res = upsert_finding_for_verdict(
        _verdict(conv), conv, target_id=env["target_id"], campaign_id="camp-1",
        findings=env["findings"], forbidden_tools={"delete_record"},
    )
    assert res.action == "created" and res.record.status == "open"
    assert res.record.component == "tool:delete_record"
    assert res.record.finding_id == finding_id(env["target_id"], "tool:delete_record", "tool_misuse", "ASI02")
    assert "delete_record" in res.record.title and res.record.seen_in_campaigns == ["camp-1"]


def test_failed_opens_nothing(env):
    conv = mk(env, ["fine"])
    assert upsert_finding_for_verdict(
        _verdict(conv, "failed", first=None, severity="info"), conv,
        target_id=env["target_id"], campaign_id="camp-1", findings=env["findings"],
    ) is None
    assert env["findings"].list() == []


# ── lifecycle (B9) ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("verdict", ["inconclusive", "unconfirmed"])
def test_inconclusive_and_unconfirmed_open_needs_review(env, verdict):
    conv = mk(env, ["hmm"])
    res = upsert_finding_for_verdict(
        _verdict(conv, verdict, first=None), conv, target_id=env["target_id"],
        campaign_id="camp-1", findings=env["findings"],
    )
    assert res.record.status == "needs_review"
    events = env["findings"].events(res.record.finding_id)
    assert [e.to_status for e in events] == ["open", "needs_review"]
    assert events[-1].reviewer_id == "system:evaluator"


def test_confirmed_promotes_needs_review_and_never_downgrades(env):
    f = env["findings"]
    conv = mk(env, ["x"])
    kw = dict(target_id=env["target_id"], campaign_id="camp-1", findings=f)
    first = upsert_finding_for_verdict(_verdict(conv, "inconclusive", first=None), conv, **kw)
    assert first.record.status == "needs_review"
    again = upsert_finding_for_verdict(_verdict(conv, "inconclusive", first=None), conv, **kw)
    assert again.action == "merged_exact" and again.record.status == "needs_review"
    up = upsert_finding_for_verdict(_verdict(conv, "confirmed"), conv, **kw)
    assert up.record.status == "open"
    down = upsert_finding_for_verdict(_verdict(conv, "inconclusive", first=None), conv, **kw)
    assert down.record.status == "open"


# ── semantic dedup ───────────────────────────────────────────────────────────


def test_semantic_dedup_merges_above_threshold_and_respects_override(env):
    f, audit = env["findings"], env["audit"]
    vectors = {"tool:remove_record": _vec(1.0, 0.0), "tool:delete_record": _vec(0.99, 0.05),
               "tool:send_email": _vec(0.0, 1.0)}

    def embedder(text):
        return next(v for k, v in vectors.items() if k in text)

    def upsert(tool, **kw):
        conv = mk(env, ["ok"], tools=[[tool]], technique="tool_misuse")
        return upsert_finding_for_verdict(
            _verdict(conv), conv, target_id=env["target_id"], campaign_id="camp-1",
            findings=f, audit=audit, embedder=embedder, dedup_threshold=0.95, **kw,
        )

    base = upsert("remove_record")
    dup = upsert("delete_record")
    assert dup.action == "merged_similar" and dup.merged_into == base.record.finding_id
    assert dup.similarity >= 0.95
    assert len(f.list()) == 1
    assert audit.list(action=DEDUP_MERGED_ACTION)[0].object == f"finding:{base.record.finding_id}"
    assert upsert("send_email").action == "created"  # dissimilar: separate finding

    # Human override: base must not absorb similar findings any more.
    with pytest.raises(ValueError):
        mark_distinct(audit, base.record.finding_id, reviewer_id="", rationale="x")
    mark_distinct(audit, base.record.finding_id, reviewer_id="alice", rationale="different tools")
    vectors["tool:purge_record"] = _vec(0.995, 0.02)
    assert upsert("purge_record").action == "created"
    # Per-call opt out.
    vectors["tool:wipe_record"] = _vec(0.995, 0.03)
    assert upsert("wipe_record", dedup=False).action == "created"


def test_dedup_without_embedder_merges_exact_only(env):
    conv = mk(env, ["ok"], tools=[["a_tool"]])
    kw = dict(target_id=env["target_id"], campaign_id="camp-1", findings=env["findings"])
    assert upsert_finding_for_verdict(_verdict(conv), conv, **kw).action == "created"
    assert upsert_finding_for_verdict(_verdict(conv), conv, **kw).action == "merged_exact"


# ── pipeline ─────────────────────────────────────────────────────────────────


def _store(env, conv):
    env["conversations"].create(conv)


def test_evaluate_conversation_persists_verdict_and_finding_from_raw_text(env):
    secret_reply = "Reference CANARY-TEST-0001"  # redacted on default reads
    conv = conversation(["hello", secret_reply], hits=[[], ["canary_leak"]], campaign_id="camp-1")
    env["conversations"].create(conv, canary_values=["CANARY-TEST-0001"])
    llm = FakeJudgeLLM(fixed(out("unsafe", first=1)))
    deps = EvaluationDeps(
        judge=Judge(llm, k=3, system_prompt="s"),
        verdicts=env["verdicts"], conversations=env["conversations"], campaigns=env["campaigns"],
        findings=env["findings"], audit=env["audit"], settings=EvaluationSettings(),
    )
    v = asyncio.run(evaluate_conversation(conv.conversation_id, deps))
    assert v.verdict == "confirmed" and v.first_failing_turn == 1 and v.severity == "critical"
    assert "CANARY-TEST-0001" in llm.messages[0]  # judged the raw text (B5)
    assert any(e.actor == "system:evaluator" for e in env["audit"].list(action="evidence.read_raw"))
    stored = env["verdicts"].get(conv.conversation_id)
    assert stored.verdict == "confirmed" and len(stored.judge_votes) == 3
    assert deps.last_finding.record.target_id == env["target_id"]
    assert deps.last_finding.record.status == "open"


def test_evaluate_conversation_judge_down_is_inconclusive_needs_review(env):
    conv = conversation(["fine"], campaign_id="camp-1")
    deps = EvaluationDeps(
        judge=Judge(FakeJudgeLLM(fixed(RuntimeError("down"))), k=3, system_prompt="s"),
        verdicts=env["verdicts"], findings=env["findings"], target_id=env["target_id"],
        settings=EvaluationSettings(),
    )
    _store(env, conv)
    v = asyncio.run(evaluate_conversation(conv, deps))
    assert v.verdict == "inconclusive"
    assert deps.last_finding.record.status == "needs_review"


def test_compute_technique_results_stores_rates(env):
    convs = []
    for i, verdict in enumerate(["confirmed", "failed", "failed", "inconclusive"]):
        c = conversation(["x"], campaign_id="camp-1", technique="prompt_injection")
        c = c.model_copy(update={"trial_index": i})
        env["conversations"].create(c)
        env["verdicts"].save(_verdict(c, verdict, first=None if verdict != "confirmed" else 0))
        convs.append(c)
    extra = conversation(["x"], campaign_id="camp-1", technique="jailbreak")
    env["conversations"].create(extra)  # no verdict: not a trial
    results = compute_technique_results(
        "camp-1", conversations=env["conversations"], verdicts=env["verdicts"],
        campaigns=env["campaigns"],
    )
    by = {r.technique: r for r in results}
    assert (by["prompt_injection"].trials, by["prompt_injection"].confirmed) == (3, 1)
    assert by["jailbreak"].trials == 0
    assert env["campaigns"].technique_results("camp-1") == results
