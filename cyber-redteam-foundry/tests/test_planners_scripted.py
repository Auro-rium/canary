# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""WP4 ScriptedPlanner: deterministic campaigns through engine.run_campaign,
branches, end conditions, resume safety and guard rails.

Every message is benign placeholder text; deny-category tests use
placeholder markers, never real content.
"""

from __future__ import annotations

import asyncio

import pytest
from engine_support import _key, build, factory, new_campaign_id  # noqa: F401

from cyberredteam.contracts import Turn
from cyberredteam.engine import ConversationState, MonitorHit, MonitorResult, run_campaign
from cyberredteam.planners import (
    DenyCategoryChecker,
    GuardRails,
    PackLoader,
    PackValidationError,
    PlannerDenyCategory,
    PlannerMessageTooLong,
    PlannerScopeViolation,
    ScriptedPlanner,
    TechniqueMismatch,
    make_planner_factory,
    parse_pack,
)

MARKER_CHECKER = DenyCategoryChecker({"category_a": [r"<<deny:category_a>>"]})


def _run(h, campaign_id):
    return asyncio.run(run_campaign(h.request, campaign_id, h.deps))


def _transcripts(h, outcome):
    out = {}
    for res in outcome.conversations:
        conv = h.conversations.get(res.conversation_id, raw=True, actor="test")
        out[(res.technique, res.trial_index)] = (
            conv.status,
            [(t.message, t.response_text, t.http_status, t.monitor_hits) for t in conv.turns],
        )
    return out


def _state(technique="t", turns=(), conversation_id="c1"):
    turns = list(turns)
    return ConversationState(
        campaign_id="camp", conversation_id=conversation_id, technique=technique, trial_index=0,
        turns=turns, max_turns=10, remaining_turns=10 - len(turns),
    )


def _turn(i, message="m", response="ok", hits=()):
    return Turn(conversation_id="c1", index=i, message=message, response_text=response,
                latency_ms=1.0, monitor_hits=list(hits))


def _pack(**over):
    data = {"name": "p", "version": 1, "technique": "t",
            "turns": [{"message": "one"}, {"message": "two"}, {"message": "three"}]}
    data.update(over)
    return parse_pack(data)


# ── Full campaigns through the engine ────────────────────────────────────────


def test_smoke_packs_run_full_campaign_deterministically(factory):
    techniques = ["smoke_greeting", "smoke_context_retention"]
    results = []
    for _ in range(2):  # two fresh harnesses: a re-run of one id would skip
        h = build(factory, techniques=techniques, trials_per_technique=2, max_turns=6)
        h.deps.planner_factory = make_planner_factory("scripted")
        outcome = _run(h, new_campaign_id())
        assert outcome.status == "completed"
        results.append(_transcripts(h, outcome))
    assert results[0] == results[1]
    greeting = results[0][("smoke_greeting", 0)]
    assert greeting[0] == "completed"
    assert [m for m, *_ in greeting[1]] == ["Hello!", "What is your name?", "Thanks, goodbye."]
    recall = results[0][("smoke_context_retention", 1)]
    assert recall[0] == "completed" and len(recall[1]) == 2
    assert all(status == 200 for _, (_, turns) in results[0].items() for *_, status, _ in turns)


class _MarkerMonitor:
    """Benign test monitor: a non-stopping hit on the turn with ``index``."""

    def __init__(self, index: int, name: str = "smoke_marker"):
        self.index, self.name = index, name

    async def check(self, turn, context):
        if turn.index == self.index:
            return MonitorResult(hits=[MonitorHit(name=self.name, severity="low")])
        return MonitorResult()


def test_branch_on_monitor_hit_through_engine(factory, tmp_path):
    (tmp_path / "branch.yaml").write_text(
        "name: branchy\nversion: 1\ntechnique: smoke_branch\n"
        "turns:\n  - message: main 0\n  - message: main 1\n  - message: main 2\n"
        "branches:\n  smoke_marker:\n    turns:\n      - message: branch 0\n      - message: branch 1\n",
        encoding="utf-8",
    )
    h = build(factory, techniques=["smoke_branch"], max_turns=8)
    h.deps.planner_factory = make_planner_factory("scripted", packs_dir=tmp_path)
    h.deps.monitors = [*h.deps.monitors, _MarkerMonitor(index=0)]
    outcome = _run(h, new_campaign_id())
    (status, turns), = _transcripts(h, outcome).values()
    assert status == "completed"
    assert [m for m, *_ in turns] == ["main 0", "branch 0", "branch 1"]


def test_technique_mismatch_on_pinned_pack_errors_conversation(factory):
    h = build(factory, techniques=["smoke_greeting"], max_turns=3)
    h.deps.planner_factory = make_planner_factory("scripted", pack="smoke-context-retention")
    outcome = _run(h, new_campaign_id())
    assert [c.status for c in outcome.conversations] == ["error"]
    assert h.fake.requests == []  # nothing was sent


def test_scope_classifier_denial_stops_conversation_as_planner_guardrail(factory):
    seen = []

    def classifier(technique, message):
        seen.append(technique)
        return message != "What is your name?"

    h = build(factory, techniques=["smoke_greeting"], max_turns=5)
    h.deps.planner_factory = make_planner_factory("scripted", scope_classifier=classifier)
    outcome = _run(h, new_campaign_id())
    (status, turns), = _transcripts(h, outcome).values()
    assert status == "stopped_planner_guardrail"  # never "completed": a guard stop is not a clean run
    assert [m for m, *_ in turns] == ["Hello!"]
    assert set(seen) == {"smoke_greeting"}


# ── Unit: script position, end conditions, resume ────────────────────────────


def test_position_is_derived_from_transcript_not_instance_state():
    pack = _pack()
    first = ScriptedPlanner(pack, "t")
    assert asyncio.run(first.next_turn(_state())).message == "one"
    # A fresh planner (the engine builds one on resume) continues from the transcript.
    fresh = ScriptedPlanner(pack, "t")
    nxt = asyncio.run(fresh.next_turn(_state(turns=[_turn(0), _turn(1)])))
    assert nxt.message == "three" and "step=2" in nxt.intent_note
    assert asyncio.run(fresh.next_turn(_state(turns=[_turn(i) for i in range(3)]))) is None


def test_branch_taken_once_and_replayed_on_resume():
    pack = _pack(branches={
        "hit_a": {"turns": [{"message": "a0"}, {"message": "a1"}]},
        "hit_b": {"turns": [{"message": "b0"}]},
    })
    p = ScriptedPlanner(pack, "t")
    # Turn 0 had both hits: pack order picks hit_a. A later hit_b is ignored.
    turns = [_turn(0, hits=["hit_b", "hit_a"])]
    assert asyncio.run(p.next_turn(_state(turns=turns))).message == "a0"
    turns.append(_turn(1, hits=["hit_b"]))
    assert asyncio.run(p.next_turn(_state(turns=turns))).message == "a1"
    turns.append(_turn(2))
    assert asyncio.run(p.next_turn(_state(turns=turns))) is None


def test_end_conditions():
    pack = _pack(end={"on_monitor_hits": ["stop_me"], "on_response_contains": ["GoodBye"]})
    p = ScriptedPlanner(pack, "t")
    assert asyncio.run(p.next_turn(_state(turns=[_turn(0, hits=["stop_me"])]))) is None
    assert asyncio.run(p.next_turn(_state(turns=[_turn(0, response="ok, goodbye!")]))) is None
    assert asyncio.run(p.next_turn(_state(turns=[_turn(0)]))).message == "two"


def test_technique_mismatch_checks():
    with pytest.raises(TechniqueMismatch):
        ScriptedPlanner(_pack(), "other")
    p = ScriptedPlanner(_pack(), "t")
    with pytest.raises(TechniqueMismatch):
        asyncio.run(p.next_turn(_state(technique="other")))


# ── Guard rails on packs ─────────────────────────────────────────────────────


def test_length_cap_rejects_pack_at_load(tmp_path):
    pack = _pack(turns=[{"message": "x" * 11}])
    with pytest.raises(PackValidationError, match="cap is 10"):
        ScriptedPlanner(pack, "t", GuardRails(max_message_chars=10))
    (tmp_path / "long.yaml").write_text(
        "name: long\nversion: 1\ntechnique: t\nturns:\n  - message: " + "y" * 20 + "\n",
        encoding="utf-8",
    )
    with pytest.raises(PackValidationError):
        make_planner_factory("scripted", packs_dir=tmp_path, max_message_chars=10)
    # At runtime the same cap is enforced (reject, not truncate).
    guards = GuardRails(max_message_chars=10)
    with pytest.raises(PlannerMessageTooLong):
        guards.check("z" * 11, planner="scripted", technique="t")


def test_deny_category_rejects_pack_and_runtime_message():
    pack = _pack(branches={"h": {"turns": [{"message": "x <<deny:category_a>> y"}]}})
    with pytest.raises(PackValidationError, match="category_a"):
        ScriptedPlanner(pack, "t", GuardRails(deny_checker=MARKER_CHECKER))
    guards = GuardRails(deny_checker=MARKER_CHECKER)
    with pytest.raises(PlannerDenyCategory) as err:
        guards.check("<<DENY:CATEGORY_A>>", planner="scripted", technique="t")
    assert "category_a" in str(err.value) and "<<" not in str(err.value)


def test_scope_classifier_error_fails_closed():
    def broken(technique, message):
        raise RuntimeError("classifier down")

    guards = GuardRails(scope_classifier=broken)
    with pytest.raises(PlannerScopeViolation, match="classifier_error=RuntimeError"):
        guards.check("hello", planner="scripted", technique="t")


def test_default_deny_categories_cover_attacker_hard_refusals_and_pass_smoke_packs():
    checker = GuardRails().deny_checker
    assert {"csam", "cbrn_weapons", "conventional_weapons", "mass_casualty",
            "real_person_targeting"} <= set(checker.categories)
    for pack in PackLoader().packs():
        assert all(checker.check(m) is None for m in pack.all_messages())
