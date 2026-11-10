"""Repositories on SQLite (always) and Postgres (when CANARY_TEST_DATABASE_URL is set)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from storage_v2_support import (
    make_conversation,
    make_policy,
    make_target,
    make_turn,
    make_verdict,
    migrate_down,
    migrate_up,
    pg_url,
)

from cyberredteam.contracts import TechniqueResult
from cyberredteam.storage.v2.db import make_engine, make_session_factory, session_scope
from cyberredteam.storage.v2.repositories import (
    AuditRepo,
    BudgetLedgerRepo,
    CampaignRepo,
    ConversationRepo,
    FindingRecord,
    FindingRepo,
    InvalidTransition,
    SqlTargetStore,
    VerdictRepo,
)
from cyberredteam.storage.v2.retention import purge_expired_evidence

BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(
    not pg_url(), reason="CANARY_TEST_DATABASE_URL not set"))]


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", Fernet.generate_key().decode())


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
def seeded(factory):
    """A target + campaign + conversation ready for use."""
    targets = SqlTargetStore(factory)
    target = make_target()
    targets.create(target)
    CampaignRepo(factory).create("camp-1", target.target_id, make_policy(), created_by="alice")
    conv = make_conversation("camp-1")
    ConversationRepo(factory).create(conv)
    return target, conv


# ── targets ──────────────────────────────────────────────────────────────────


def test_target_store_crud_and_secret_not_plaintext_at_rest(factory):
    store = SqlTargetStore(factory)
    t = make_target(secret="tok-VERY-SECRET-123")
    assert store.create(t) == t.target_id
    got = store.get(t.target_id)
    assert got.auth.token.get_secret_value() == "tok-VERY-SECRET-123"
    assert got.verified is False and got.endpoint == t.endpoint
    assert [x.target_id for x in store.list()] == [t.target_id]
    assert store.get("00000000-0000-4000-8000-000000000000") is None
    with session_scope(factory) as s:
        raw = s.execute(text("SELECT secrets FROM target_secrets")).scalar()
        public = s.execute(text("SELECT auth_public FROM targets")).scalar()
    assert "VERY-SECRET" not in raw and "VERY-SECRET" not in str(public)
    with pytest.raises(ValueError):
        store.create(t)


def test_target_create_never_stores_verified_true(factory):
    store = SqlTargetStore(factory)
    t = make_target().model_copy(update={"verified": True})
    store.create(t)
    assert store.get(t.target_id).verified is False


def test_target_verification_lifecycle(factory):
    store = SqlTargetStore(factory)
    t = make_target()
    store.create(t)
    assert store.get_verification_token_hash(t.target_id) is None
    store.set_verification_token_hash(t.target_id, "h1")
    store.set_verification_token_hash(t.target_id, "h2")
    assert store.get_verification_token_hash(t.target_id) == "h2"
    store.set_verified(t.target_id, "dns_txt")
    assert store.get(t.target_id).verified is True
    assert store.get_verification_token_hash(t.target_id) == "h2"
    with pytest.raises(KeyError):
        store.set_verified("00000000-0000-4000-8000-000000000000", "dns_txt")


def test_target_store_never_logs_secrets(factory, caplog):
    caplog.set_level(logging.DEBUG)
    store = SqlTargetStore(factory)
    t = make_target(secret="tok-LOGLEAK-999")
    store.create(t)
    store.get(t.target_id)
    store.list()
    store.set_verified(t.target_id, "http_file")
    assert "LOGLEAK" not in caplog.text
    assert "LOGLEAK" not in repr(store.get(t.target_id))


# ── campaigns ────────────────────────────────────────────────────────────────


def test_campaign_repo(factory):
    t = make_target()
    SqlTargetStore(factory).create(t)
    repo = CampaignRepo(factory)
    rec = repo.create("c9", t.target_id, make_policy(), created_by="bob")
    assert rec.status == "queued" and rec.policy.trials_per_technique == 2
    repo.set_status("c9", "running")
    repo.set_status("c9", "completed")
    got = repo.get("c9")
    assert got.status == "completed" and got.finished_at is not None
    assert [c.campaign_id for c in repo.list_for_target(t.target_id)] == ["c9"]
    repo.save_technique_results("c9", [TechniqueResult.from_counts("prompt_injection", 5, 2)])
    repo.save_technique_results("c9", [TechniqueResult.from_counts("prompt_injection", 5, 3)])
    res = repo.technique_results("c9")
    assert len(res) == 1 and res[0].confirmed == 3
    with pytest.raises(KeyError):
        repo.set_status("nope", "running")


# ── conversations / turns ────────────────────────────────────────────────────


def test_append_turn_is_immediately_durable_and_encrypted(factory, seeded):
    _, conv = seeded
    repo = ConversationRepo(factory)
    repo.append_turn(make_turn(conv.conversation_id, 0, message="mail me at a@b.io",
                               response_text="ok"))
    # Visible to a brand-new connection right away: committed before append_turn returned.
    fresh = make_session_factory(make_engine(str(factory.kw["bind"].url.render_as_string(False))))
    with session_scope(fresh) as s:
        rows = s.execute(text("SELECT message, redacted_message_preview FROM turns")).all()
    assert len(rows) == 1
    assert "a@b.io" not in rows[0][0]                      # ciphertext
    assert rows[0][1] == "mail me at [REDACTED:email]"     # plaintext, redacted
    repo.append_turn(make_turn(conv.conversation_id, 1))
    assert [t.index for t in repo.get(conv.conversation_id, raw=True, actor="a").turns] == [0, 1]


def test_get_redacted_by_default_raw_requires_actor_and_is_audited(factory, seeded):
    _, conv = seeded
    repo = ConversationRepo(factory)
    repo.append_turn(make_turn(conv.conversation_id, 0, message="my ssn is 123-45-6789",
                               response_text="key sk-abcdefghijklmnopqrstuvwx"))
    red = repo.get(conv.conversation_id)
    assert "123-45-6789" not in red.turns[0].message
    assert "sk-abcdef" not in red.turns[0].response_text
    with pytest.raises(ValueError):
        repo.get(conv.conversation_id, raw=True)
    assert AuditRepo(factory).list(action="evidence.read_raw") == []
    raw = repo.get(conv.conversation_id, raw=True, actor="reviewer-1")
    assert raw.turns[0].message == "my ssn is 123-45-6789"
    audit = AuditRepo(factory).list(action="evidence.read_raw")
    assert len(audit) == 1 and audit[0].actor == "reviewer-1"
    assert audit[0].object == f"conversation:{conv.conversation_id}"


def test_canary_values_redacted_in_preview_and_hits_recorded(factory, seeded):
    _, conv = seeded
    repo = ConversationRepo(factory)
    repo.append_turn(make_turn(conv.conversation_id, 0, response_text="the code is ZEBRA-42"),
                     canary_values=["ZEBRA-42"])
    assert "ZEBRA" not in repo.get(conv.conversation_id).turns[0].response_text
    with session_scope(factory) as s:
        assert "canary" in s.execute(text("SELECT redaction_hits FROM turns")).scalar().__str__()


def test_turn_roundtrip_fields_and_status(factory, seeded):
    _, conv = seeded
    repo = ConversationRepo(factory)
    repo.append_turn(make_turn(
        conv.conversation_id, 0, http_status=200, monitor_hits=["pii"],
        tool_calls=[{"name": "send_email", "arguments": {"to": "x"}}]))
    repo.set_status(conv.conversation_id, "completed", target_session_ref="sess-1")
    got = repo.get(conv.conversation_id, raw=True, actor="t")
    assert got.status == "completed" and got.target_session_ref == "sess-1"
    t = got.turns[0]
    assert t.http_status == 200 and t.monitor_hits == ["pii"] and t.tool_calls[0].name == "send_email"
    assert repo.list_for_campaign("camp-1") == [conv.conversation_id]
    assert repo.get("missing") is None


def test_duplicate_turn_index_rejected(factory, seeded):
    _, conv = seeded
    repo = ConversationRepo(factory)
    repo.append_turn(make_turn(conv.conversation_id, 0))
    with pytest.raises(IntegrityError):
        repo.append_turn(make_turn(conv.conversation_id, 0))


# ── verdicts ─────────────────────────────────────────────────────────────────


def test_verdict_roundtrip_and_replace(factory, seeded):
    _, conv = seeded
    repo = VerdictRepo(factory)
    v = make_verdict(conv.conversation_id)
    repo.save(v)
    got = repo.get(conv.conversation_id)
    assert got == v
    with session_scope(factory) as s:
        assert "leaked the canary" not in s.execute(text("SELECT rationale FROM verdicts")).scalar()
    repo.save(v.model_copy(update={"verdict": "unconfirmed", "judge_votes": v.judge_votes[:1]}))
    again = repo.get(conv.conversation_id)
    assert again.verdict == "unconfirmed" and len(again.judge_votes) == 1
    assert [x.conversation_id for x in repo.list_for_campaign("camp-1")] == [conv.conversation_id]
    assert repo.get("missing") is None


# ── findings ─────────────────────────────────────────────────────────────────


def _finding(target, fid="f1", severity="medium"):
    return FindingRecord(finding_id=fid, target_id=target.target_id, technique="prompt_injection",
                         asi_class="ASI01", severity=severity, title="t")


def test_finding_upsert_merges_and_severity_only_increases(factory, seeded):
    target, _ = seeded
    repo = FindingRepo(factory)
    a = repo.upsert(_finding(target, severity="high"), campaign_id="camp-1")
    assert a.status == "open" and a.seen_in_campaigns == ["camp-1"]
    CampaignRepo(factory).create("camp-2", target.target_id, make_policy())
    b = repo.upsert(_finding(target, severity="low"), campaign_id="camp-2")
    assert b.severity == "high" and b.seen_in_campaigns == ["camp-1", "camp-2"]
    assert b.last_seen_campaign == "camp-2" and b.first_seen_campaign == "camp-1"
    c = repo.upsert(_finding(target, severity="critical"), campaign_id="camp-2")
    assert c.severity == "critical" and c.seen_in_campaigns == ["camp-1", "camp-2"]


def test_finding_transitions_store_reviewer_rationale_and_audit(factory, seeded):
    target, _ = seeded
    repo = FindingRepo(factory)
    repo.upsert(_finding(target), campaign_id="camp-1")
    repo.transition("f1", "needs_review", reviewer_id="alice")
    repo.transition("f1", "open", reviewer_id="alice", rationale="re-checked")
    repo.transition("f1", "inconclusive")
    repo.transition("f1", "wont_fix", reviewer_id="bob", rationale="accepted risk, ticket 12")
    events = repo.events("f1")
    assert [(e.from_status, e.to_status) for e in events] == [
        (None, "open"), ("open", "needs_review"), ("needs_review", "open"),
        ("open", "inconclusive"), ("inconclusive", "wont_fix"),
    ]
    last = events[-1]
    assert last.reviewer_id == "bob" and last.rationale == "accepted risk, ticket 12"
    audit = AuditRepo(factory).list(action="finding.transition", obj="finding:f1")
    assert len(audit) == 4 and audit[-1].actor == "bob"
    assert audit[-1].details["rationale"] == "accepted risk, ticket 12"
    assert repo.get("f1").status == "wont_fix"


def test_finding_transition_rules(factory, seeded):
    target, _ = seeded
    repo = FindingRepo(factory)
    repo.upsert(_finding(target), campaign_id="camp-1")
    with pytest.raises(InvalidTransition):
        repo.transition("f1", "false_positive")                    # needs reviewer + rationale
    with pytest.raises(InvalidTransition):
        repo.transition("f1", "false_positive", reviewer_id="a")   # needs rationale
    with pytest.raises(InvalidTransition):
        repo.transition("f1", "open", reviewer_id="a", rationale="x")  # open -> open
    with pytest.raises(InvalidTransition):
        repo.transition("f1", "bogus", reviewer_id="a", rationale="x")
    repo.transition("f1", "false_positive", reviewer_id="a", rationale="benign")
    for nxt in ("open", "wont_fix", "inconclusive", "needs_review"):
        with pytest.raises(InvalidTransition):
            repo.transition("f1", nxt, reviewer_id="a", rationale="x")  # terminal
    with pytest.raises(KeyError):
        repo.transition("nope", "inconclusive")
    assert repo.get("f1").status == "false_positive"
    assert len(repo.events("f1")) == 2  # failed attempts left no events


def test_find_similar(factory, seeded):
    target, _ = seeded
    repo = FindingRepo(factory)
    e1 = [1.0] + [0.0] * 383
    e2 = [0.0, 1.0] + [0.0] * 382
    repo.upsert(_finding(target, "fa"), campaign_id="camp-1", embedding=e1)
    repo.upsert(_finding(target, "fb"), campaign_id="camp-1", embedding=e2)
    near = [0.99, 0.05] + [0.0] * 382
    hits = repo.find_similar(target.target_id, near)
    assert [h[0] for h in hits] == ["fa"] and hits[0][1] > 0.99
    repo.transition("fa", "inconclusive")
    assert repo.find_similar(target.target_id, near) == []
    assert [h[0] for h in repo.find_similar(target.target_id, near, open_only=False)] == ["fa"]


# ── audit / budget ───────────────────────────────────────────────────────────


def test_audit_redacts_details(factory):
    repo = AuditRepo(factory)
    repo.record("alice", "target.verify", "target:1", {"note": "contact a@b.io", "n": 3})
    (e,) = repo.list(action="target.verify")
    assert e.details == {"note": "contact [REDACTED:email]", "n": 3}


def test_budget_ledger_sums_by_kind(factory, seeded):
    repo = BudgetLedgerRepo(factory)
    repo.add("camp-1", "requests", 1)
    repo.add("camp-1", "requests", 2)
    repo.add("camp-1", "usd", 0.25)
    repo.add("camp-1", "usd", 0.5)
    repo.add("camp-1", "tokens", 1000)
    assert repo.total("camp-1", "requests") == 3
    assert repo.total("camp-1", "usd") == pytest.approx(0.75)
    assert repo.totals("camp-1") == {"requests": 3, "tokens": 1000, "usd": pytest.approx(0.75)}
    assert repo.total("other", "usd") == 0
    with pytest.raises(ValueError):
        repo.add("camp-1", "bogus", 1)
    with pytest.raises(ValueError):
        repo.add("camp-1", "usd", -1)


# ── retention ────────────────────────────────────────────────────────────────


def _age_turns(factory, conversation_id, days):
    old = datetime.now(timezone.utc) - timedelta(days=days)
    with session_scope(factory) as s:
        s.execute(text("UPDATE turns SET created_at = :d WHERE conversation_id = :c"),
                  {"d": old, "c": conversation_id})


def test_retention_purge_counts_and_per_target_override(factory):
    targets, camps, convs = SqlTargetStore(factory), CampaignRepo(factory), ConversationRepo(factory)
    t1, t2 = make_target(), make_target()
    targets.create(t1)
    targets.create(t2)
    targets.set_retention_days(t2.target_id, 5)
    ids = {}
    for name, t in (("a", t1), ("b", t2)):
        camps.create(f"c-{name}", t.target_id, make_policy())
        conv = make_conversation(f"c-{name}")
        convs.create(conv)
        convs.append_turn(make_turn(conv.conversation_id, 0))
        convs.append_turn(make_turn(conv.conversation_id, 1))
        ids[name] = conv.conversation_id
    _age_turns(factory, ids["a"], 10)   # default 30 days: kept
    _age_turns(factory, ids["b"], 10)   # override 5 days: purged
    counts = purge_expired_evidence(factory, default_days=30)
    assert counts == {"targets_scanned": 2, "turns_purged": 2}
    a = convs.get(ids["a"], raw=True, actor="t")
    b = convs.get(ids["b"], raw=True, actor="t")
    assert a.turns[0].message == "hello 0"
    assert b.turns[0].message == "" and b.turns[0].response_text == ""
    assert convs.get(ids["b"]).turns[0].message == "hello 0"  # redacted preview survives
    assert purge_expired_evidence(factory, default_days=30)["turns_purged"] == 0  # idempotent
    _age_turns(factory, ids["a"], 40)
    assert purge_expired_evidence(factory, default_days=30)["turns_purged"] == 2
    assert len(AuditRepo(factory).list(action="retention.purge")) == 3
