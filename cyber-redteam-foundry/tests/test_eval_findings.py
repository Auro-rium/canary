"""B7/B9 findings and the evaluate_conversation pipeline, on SQLite and Postgres."""

from __future__ import annotations

import asyncio
import threading

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
    InvalidTransition,
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
    ns = conversation(["ok"], tools=[[ToolCallObservation(name="lookup_order_status"),
                                      ToolCallObservation(name="Functions.Delete_Record")]])
    assert resolve_component(ns, v, {"delete_record"}) == "tool:delete_record"
    assert resolve_component(ns, v, {"functions.delete_record"}) == "tool:delete_record"
    a_ns = conversation(["ok"], tools=[[ToolCallObservation(name="a.delete_record")]])
    b_ns = conversation(["ok"], tools=[[ToolCallObservation(name="b.delete_record")]])
    assert resolve_component(a_ns, v) == "tool:a.delete_record"
    assert resolve_component(b_ns, v) == "tool:b.delete_record"
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
    # Created atomically in needs_review: never visible as open (review B2).
    assert [(e.from_status, e.to_status) for e in events] == [(None, "needs_review")]


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


# ── concurrency (review B2) ──────────────────────────────────────────────────


def test_race_inconclusive_never_demotes_concurrent_confirmed(env):
    """B read "no finding" before A's confirmed verdict landed; B's inconclusive
    upsert must merge as a sighting and leave the finding open."""
    conv_a, conv_b = mk(env, ["leak"]), mk(env, ["meh"])
    repo = env["findings"]
    real_get = repo.get
    state = {"first": True}

    def racing_get(fid):
        if state["first"]:
            state["first"] = False
            upsert_finding_for_verdict(_verdict(conv_a), conv_a, target_id=env["target_id"],
                                       campaign_id="camp-1", findings=repo)
            return None
        return real_get(fid)

    repo.get = racing_get
    try:
        upsert_finding_for_verdict(_verdict(conv_b, "inconclusive", first=None), conv_b,
                                   target_id=env["target_id"], campaign_id="camp-1", findings=repo)
    finally:
        repo.get = real_get
    recs = repo.list()
    assert len(recs) == 1 and recs[0].status == "open"
    assert all(e.to_status != "needs_review" for e in repo.events(recs[0].finding_id))


def test_race_confirmed_after_concurrent_inconclusive_is_promoted(env):
    conv_a, conv_b = mk(env, ["meh"]), mk(env, ["leak"])
    repo = env["findings"]
    real_get = repo.get
    state = {"first": True}

    def racing_get(fid):
        if state["first"]:
            state["first"] = False
            upsert_finding_for_verdict(_verdict(conv_a, "inconclusive", first=None), conv_a,
                                       target_id=env["target_id"], campaign_id="camp-1", findings=repo)
            return None
        return real_get(fid)

    repo.get = racing_get
    try:
        upsert_finding_for_verdict(_verdict(conv_b), conv_b, target_id=env["target_id"],
                                   campaign_id="camp-1", findings=repo)
    finally:
        repo.get = real_get
    (rec,) = repo.list()
    assert rec.status == "open"
    assert [e.to_status for e in repo.events(rec.finding_id)] == ["needs_review", "open"]


def test_upsert_initial_status_only_applies_on_create(env):
    from cyberredteam.storage.v2.repositories import FindingRecord, InvalidTransition

    conv = mk(env, ["x"])
    rec = FindingRecord(finding_id="f" * 16, target_id=env["target_id"], asi_class="ASI01",
                        severity="low", conversation_id=conv.conversation_id)
    repo = env["findings"]
    assert repo.upsert(rec, initial_status="needs_review").status == "needs_review"
    repo.transition(rec.finding_id, "open", reviewer_id="alice", rationale="confirmed by hand")
    assert repo.upsert(rec, initial_status="needs_review").status == "open"
    with pytest.raises(InvalidTransition):
        repo.upsert(rec.model_copy(update={"finding_id": "e" * 16}), initial_status="wont_fix")


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


# ── human triage is never overridden by automation (re-review B2) ────────────


def _up(env, conv, verdict="confirmed"):
    first = 0 if verdict == "confirmed" else None
    return upsert_finding_for_verdict(_verdict(conv, verdict, first=first), conv,
                                      target_id=env["target_id"], campaign_id="camp-1",
                                      findings=env["findings"])


def test_repro_inconclusive_vs_confirmed(env):
    conv_a, conv_b = mk(env, ["leak"]), mk(env, ["meh"])
    repo = env["findings"]
    real_get = repo.get
    state = {"first": True}

    def racing_get(fid):
        if state["first"]:
            state["first"] = False
            _up(env, conv_a)
            return None
        return real_get(fid)

    repo.get = racing_get
    _up(env, conv_b, "inconclusive")
    repo.get = real_get
    (rec,) = repo.list()
    assert rec.status == "open"


def test_two_confirmed_race(env):
    conv_a, conv_b = mk(env, ["leak"]), mk(env, ["leak2"])
    repo = env["findings"]
    real_get = repo.get
    state = {"first": True}

    def racing_get(fid):
        if state["first"]:
            state["first"] = False
            _up(env, conv_a)
            return None
        return real_get(fid)

    repo.get = racing_get
    _up(env, conv_b)
    repo.get = real_get
    (rec,) = repo.list()
    assert rec.status == "open"
    assert [e.to_status for e in repo.events(rec.finding_id)] == ["open"]


@pytest.mark.parametrize("human", ["false_positive", "wont_fix", "open"])
def test_confirmed_promotion_races_human_on_needs_review(env, human):
    """Finding exists as needs_review; confirmed upsert reads it; a human acts before the promote."""
    conv_a, conv_b = mk(env, ["meh"]), mk(env, ["leak"])
    _up(env, conv_a, "inconclusive")
    repo = env["findings"]
    real_t = repo.transition
    state = {"first": True}

    def racing_t(fid, new, **kw):
        if state["first"]:
            state["first"] = False
            real_t(fid, human, reviewer_id="alice", rationale="triaged by hand")
        return real_t(fid, new, **kw)

    repo.transition = racing_t
    res = _up(env, conv_b)
    repo.transition = real_t
    (rec,) = repo.list()
    assert rec.status == human
    assert res.record.status == human


@pytest.mark.parametrize("human", ["inconclusive", "needs_review"])
def test_human_demotion_then_confirmed(env, human):
    """Human demotes open -> inconclusive/needs_review; a later confirmed verdict arrives."""
    conv_a, conv_b = mk(env, ["leak"]), mk(env, ["leak2"])
    _up(env, conv_a)
    repo = env["findings"]
    (rec,) = repo.list()
    repo.transition(rec.finding_id, human, reviewer_id="alice", rationale="not reproducible")
    _up(env, conv_b)
    (rec,) = repo.list()
    assert rec.status == human, "automated verdict overwrote a human triage decision"


@pytest.mark.parametrize("human", ["false_positive", "wont_fix"])
@pytest.mark.parametrize("verdict", ["confirmed", "inconclusive", "unconfirmed"])
def test_terminal_human_never_touched(env, human, verdict):
    conv_a, conv_b = mk(env, ["leak"]), mk(env, ["x"])
    _up(env, conv_a)
    repo = env["findings"]
    (rec,) = repo.list()
    repo.transition(rec.finding_id, human, reviewer_id="alice", rationale="fp")
    _up(env, conv_b, verdict)
    (rec,) = repo.list()
    assert rec.status == human


def test_threaded_mixed(env):
    """Real threads: many inconclusive + one confirmed on the same finding."""
    convs = [mk(env, [f"m{i}"]) for i in range(12)]
    barrier = threading.Barrier(len(convs))
    errors = []

    def run(i, conv):
        try:
            barrier.wait()
            _up(env, conv, "confirmed" if i == 5 else "inconclusive")
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    ts = [threading.Thread(target=run, args=(i, c)) for i, c in enumerate(convs)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, errors
    (rec,) = env["findings"].list()
    assert rec.status == "open"
    ev = [e.to_status for e in env["findings"].events(rec.finding_id)]
    assert ev[-1] == "open" and ev.count(None) == 0


def test_threaded_confirmed_vs_human(env):
    conv0 = mk(env, ["x"])
    _up(env, conv0, "inconclusive")
    (rec,) = env["findings"].list()
    convs = [mk(env, [f"m{i}"]) for i in range(8)]
    barrier = threading.Barrier(len(convs) + 1)
    errors = []

    def run(conv):
        try:
            barrier.wait()
            _up(env, conv, "confirmed")
        except Exception as e:  # noqa: BLE001
            errors.append(repr(e))

    def human():
        barrier.wait()
        try:
            env["findings"].transition(rec.finding_id, "false_positive", reviewer_id="alice", rationale="fp")
        except InvalidTransition:
            pass

    ts = [threading.Thread(target=run, args=(c,)) for c in convs] + [threading.Thread(target=human)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, errors
    final = env["findings"].get(rec.finding_id)
    ev = [(e.from_status, e.to_status, e.reviewer_id) for e in env["findings"].events(rec.finding_id)]
    # Either the human won (false_positive) or promotion won first and human then failed: open.
    if any(t == "false_positive" for _, t, _ in ev):
        assert final.status == "false_positive"


def test_human_demotion_records_skipped_promotion_in_audit(env):
    conv_a, conv_b = mk(env, ["leak"]), mk(env, ["leak2"])
    _up(env, conv_a)
    repo = env["findings"]
    (rec,) = repo.list()
    repo.transition(rec.finding_id, "needs_review", reviewer_id="alice", rationale="not reproducible")
    res = upsert_finding_for_verdict(_verdict(conv_b), conv_b, target_id=env["target_id"],
                                     campaign_id="camp-1", findings=repo, audit=env["audit"])
    assert res.record.status == "needs_review"
    (note,) = env["audit"].list(action="finding.promotion_skipped")
    assert note.object == f"finding:{rec.finding_id}"
    events = [(e.from_status, e.to_status, e.reviewer_id) for e in repo.events(rec.finding_id)]
    assert events[-1] == ("open", "needs_review", "alice")


def test_transition_is_compare_and_set(env):
    conv = mk(env, ["x"])
    _up(env, conv, "inconclusive")
    repo = env["findings"]
    (rec,) = repo.list()
    with pytest.raises(InvalidTransition):
        repo.transition(rec.finding_id, "open", reviewer_id="system:evaluator", rationale="x",
                        expected_from="inconclusive")
    repo.transition(rec.finding_id, "open", reviewer_id="alice", rationale="seen it")
    repo.transition(rec.finding_id, "needs_review", reviewer_id="bob", rationale="hmm")
    with pytest.raises(InvalidTransition, match="human"):
        repo.transition(rec.finding_id, "open", reviewer_id="system:evaluator", rationale="x",
                        require_system_last=True)
    assert repo.get(rec.finding_id).status == "needs_review"


def test_threaded_human_false_positive_never_overwritten(factory, tmp_path):
    """Real threads on a file DB: automated promotions race a human
    false_positive. Whenever the human's transition succeeded, it is final."""
    for round_ in range(6):
        target = make_target()
        SqlTargetStore(factory).create(target)
        camp = f"camp-t{round_}"
        CampaignRepo(factory).create(camp, target.target_id, make_policy(), created_by="op")
        e = {"target_id": target.target_id, "findings": FindingRepo(factory),
             "conversations": ConversationRepo(factory)}
        convs = []
        for i in range(7):
            c = conversation([f"m{i}"], campaign_id=camp)
            e["conversations"].create(c)
            convs.append(c)
        upsert_finding_for_verdict(_verdict(convs[0], "inconclusive", first=None), convs[0],
                                   target_id=e["target_id"], campaign_id=camp, findings=e["findings"])
        (rec,) = e["findings"].list(target_id=target.target_id)
        barrier = threading.Barrier(len(convs))
        human_ok: list[bool] = []
        errors: list[str] = []

        def automation(conv):
            try:
                barrier.wait()
                upsert_finding_for_verdict(_verdict(conv), conv, target_id=e["target_id"],
                                           campaign_id=camp, findings=e["findings"])
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))

        def human():
            barrier.wait()
            try:
                e["findings"].transition(rec.finding_id, "false_positive", reviewer_id="alice",
                                         rationale="fp")
                human_ok.append(True)
            except InvalidTransition:
                human_ok.append(False)

        ts = [threading.Thread(target=automation, args=(c,)) for c in convs[1:]]
        ts.append(threading.Thread(target=human))
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert not errors, errors
        final = e["findings"].get(rec.finding_id).status
        if human_ok == [True]:
            assert final == "false_positive", f"round {round_}: human decision overwritten"
        else:
            assert final == "open"
