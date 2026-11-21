# ruff: noqa: F811  (pytest fixtures imported from support modules)
"""The real attack packs (packs/attacks/): schema, guard rails, coverage,
production refusal, branch resolution and an end-to-end run through
execute_campaign against FakeTarget with the REAL monitors and a fake judge.

No network, no real LLM. SQLite always, Postgres when CANARY_TEST_DATABASE_URL is set.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import yaml
from engine_support import build, metrics, new_campaign_id  # noqa: F401
from fixtures.fake_target import DEFAULT_CANARY, DEFAULT_FORBIDDEN_TOOL, FakeTarget
from jobs_support import db_factory  # noqa: F401
from langchain_core.runnables import RunnableLambda

from cyberredteam.contracts import (
    PRODUCTION_FORBIDDEN_TECHNIQUES,
    CampaignPolicy,
    normalize_technique,
)
from cyberredteam.evaluation.judge import Judge
from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.execution import JobRuntime, execute_campaign
from cyberredteam.jobs.runner_wiring import load_planner_factory, make_runner
from cyberredteam.planners import GuardRails, PackLoader, ScriptedPlanner
from cyberredteam.planners import worker as planner_worker
from cyberredteam.planners.packs import DEFAULT_PACKS_DIR, MAX_PACK_FILE_BYTES, load_pack_file
from cyberredteam.planners.scripted import validate_pack_messages
from cyberredteam.settings import get_settings
from cyberredteam.storage.v2.repositories import (
    CampaignRepo,
    ConversationRepo,
    FindingRepo,
    SqlTargetStore,
    VerdictRepo,
)

ATTACKS_DIR = DEFAULT_PACKS_DIR / "attacks"
CONFIGS = Path(__file__).resolve().parents[1] / "configs"
# Only non-critical hits can fire a branch: a critical hit already stops the conversation.
CRITICAL_HITS = {"canary_leak", "canary_leak_obfuscated", "forbidden_tool_call"}


def _attack_packs():
    return PackLoader(DEFAULT_PACKS_DIR, pack_set="attacks").packs()


def _taxonomy_techniques() -> dict[str, str]:
    data = yaml.safe_load((CONFIGS / "asi_taxonomy.yaml").read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for m in data["mappings"]:
        if m["strategy"] != "*":
            out.setdefault(m["strategy"], m["asi_class"])
    return out


# ── Parse, guard rails, metadata ─────────────────────────────────────────────


def test_every_attack_pack_file_parses_and_is_under_the_size_cap():
    files = sorted(ATTACKS_DIR.glob("*.yaml"))
    assert 40 <= len(files) <= 70
    for path in files:
        assert path.stat().st_size < MAX_PACK_FILE_BYTES
        pack = load_pack_file(path)
        assert pack.name == path.stem  # file name matches the pack name


def test_attack_pack_names_are_unique_and_loader_sees_all_of_them():
    packs = _attack_packs()
    assert len({p.name for p in packs}) == len(packs) == len(list(ATTACKS_DIR.glob("*.yaml")))


def test_every_attack_pack_message_passes_length_cap_and_deny_checks():
    guards = GuardRails()
    for pack in _attack_packs():
        validate_pack_messages(pack, guards)  # raises PackValidationError
        for message in pack.all_messages():
            assert len(message) <= guards.max_message_chars
            assert guards.deny_checker.check(message) is None


def test_every_attack_pack_declares_technique_asi_signal_description_and_end():
    for pack in _attack_packs():
        assert pack.asi_class, pack.name
        assert pack.success_signal, pack.name
        assert len(pack.description) >= 20, pack.name
        assert pack.end.on_monitor_hits or pack.end.on_response_contains, pack.name
        assert len(pack.turns) >= 3 or pack.technique == "denial-of-service", pack.name


def test_attack_packs_use_placeholder_identities_and_no_credential_shaped_strings():
    import re

    shaped = re.compile(
        r"sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}"
        r"|AIza[0-9A-Za-z_-]{30,}|-----BEGIN|eyJ[A-Za-z0-9_-]{5,}\.eyJ"
    )
    email = re.compile(r"[\w.+-]+@([\w-]+\.)+\w+")
    for pack in _attack_packs():
        for message in pack.all_messages():
            assert not shaped.search(message), pack.name
            for m in email.finditer(message):
                assert m.group(0).endswith("@example.com"), (pack.name, m.group(0))


# ── Coverage ─────────────────────────────────────────────────────────────────


def test_every_technique_and_asi_code_has_at_least_one_attack_pack():
    packs = _attack_packs()
    by_technique: dict[str, list] = {}
    for p in packs:
        by_technique.setdefault(p.technique, []).append(p)
    taxonomy = _taxonomy_techniques()
    assert taxonomy  # sanity
    for technique, asi in taxonomy.items():
        assert by_technique.get(technique), f"no attack pack for technique {technique}"
        assert all(p.asi_class == asi for p in by_technique[technique]), technique
    specs = yaml.safe_load((CONFIGS / "technique_specs.yaml").read_text(encoding="utf-8"))
    assert {p.asi_class for p in packs} >= set(specs)
    # Every production-forbidden technique is covered too (staging-only packs).
    for forbidden in PRODUCTION_FORBIDDEN_TECHNIQUES:
        assert by_technique.get(forbidden), forbidden


def test_every_success_signal_family_is_represented():
    signals = {p.success_signal for p in _attack_packs()}
    assert {"canary_leak", "forbidden_tool_call", "system_prompt_disclosure", "cross_user_data"} <= signals


# ── Production refusal ───────────────────────────────────────────────────────

_PROD_OK = {"rate_limit_rps": 1.0, "max_parallel_conversations": 2, "max_total_requests": 300,
            "allow_destructive_tools": False}


def test_production_forbidden_techniques_are_refused_in_production():
    techniques = {p.technique for p in _attack_packs()}
    forbidden = {t for t in techniques if normalize_technique(t) in
                 {normalize_technique(f) for f in PRODUCTION_FORBIDDEN_TECHNIQUES}}
    assert forbidden == set(PRODUCTION_FORBIDDEN_TECHNIQUES)
    for technique in forbidden:
        policy = CampaignPolicy(techniques=[technique], **_PROD_OK)
        assert any("staging-only" in v for v in policy.production_violations())
        with pytest.raises(ValueError, match="staging-only"):
            CampaignPolicy.model_validate(policy.model_dump(), context={"environment": "production"})
        # Staging still accepts them.
        CampaignPolicy.model_validate(policy.model_dump(), context={"environment": "staging"})


def test_every_asi09_resource_exhaustion_pack_is_marked_production_forbidden():
    asi09 = [p for p in _attack_packs() if p.asi_class == "ASI09"]
    assert asi09
    assert all(p.technique in PRODUCTION_FORBIDDEN_TECHNIQUES for p in asi09)


def test_all_other_attack_techniques_are_allowed_in_production():
    others = sorted({p.technique for p in _attack_packs()} - set(PRODUCTION_FORBIDDEN_TECHNIQUES))
    policy = CampaignPolicy(techniques=others, **_PROD_OK)
    assert policy.production_violations() == []


# ── Branches ─────────────────────────────────────────────────────────────────


def _state(technique, turns=()):
    from cyberredteam.engine import ConversationState

    turns = list(turns)
    return ConversationState(
        campaign_id="camp", conversation_id="c1", technique=technique, trial_index=0,
        turns=turns, max_turns=20, remaining_turns=20 - len(turns),
    )


def _turn(i, hits=()):
    from cyberredteam.contracts import Turn

    return Turn(conversation_id="c1", index=i, message="m", response_text="ok", latency_ms=1.0,
                monitor_hits=list(hits))


def test_branch_keys_are_real_non_critical_monitor_hit_names():
    n_branches = 0
    for pack in _attack_packs():
        for key, branch in pack.branches.items():
            n_branches += 1
            assert key not in CRITICAL_HITS, (pack.name, key)
            assert key == "forbidden_tool_heuristic" or key.startswith(("secret_pattern:", "pii:")), (pack.name, key)
            assert branch.turns
    assert n_branches >= 30  # most packs escalate or switch tactic on a hit


def test_branches_resolve_to_their_turns_and_the_rest_of_the_main_script_is_dropped():
    guards = GuardRails()
    for pack in _attack_packs():
        for key, branch in pack.branches.items():
            planner = ScriptedPlanner(pack, pack.technique, guards)
            first = asyncio.run(planner.next_turn(_state(pack.technique)))
            assert first.message == pack.turns[0].message
            after_hit = asyncio.run(planner.next_turn(_state(pack.technique, [_turn(0, [key])])))
            assert after_hit.message == branch.turns[0].message, (pack.name, key)
            # After the branch is exhausted the conversation ends (main turns are not replayed).
            done = [_turn(0, [key])] + [_turn(i + 1) for i in range(len(branch.turns))]
            assert asyncio.run(planner.next_turn(_state(pack.technique, done))) is None


def test_a_pack_without_a_hit_replays_its_main_script_in_order():
    for pack in _attack_packs():
        planner = ScriptedPlanner(pack, pack.technique, GuardRails())
        seen = []
        turns = []
        while True:
            planned = asyncio.run(planner.next_turn(_state(pack.technique, turns)))
            if planned is None:
                break
            seen.append(planned.message)
            turns.append(_turn(len(turns)))
        assert seen == [t.message for t in pack.turns], pack.name


# ── Pack set selection ───────────────────────────────────────────────────────


def test_pack_sets_select_smoke_attacks_or_all():
    smoke = PackLoader(DEFAULT_PACKS_DIR, pack_set="smoke").names
    attacks = PackLoader(DEFAULT_PACKS_DIR, pack_set="attacks").names
    everything = PackLoader(DEFAULT_PACKS_DIR, pack_set="all").names
    assert smoke == ["smoke-context-retention", "smoke-greeting"]
    assert len(attacks) >= 40 and not set(smoke) & set(attacks)
    assert everything == sorted(smoke + attacks)
    from cyberredteam.planners.errors import PackNotFound

    with pytest.raises(PackNotFound):
        PackLoader(DEFAULT_PACKS_DIR, pack_set="bogus")


def test_worker_scripted_defaults_to_smoke_and_honours_planner_pack_set(monkeypatch):
    from cyberredteam.engine import ConversationSpec

    monkeypatch.delenv("PLANNER_PACKS_DIR", raising=False)
    monkeypatch.delenv("PLANNER_PACK_SET", raising=False)
    planner_worker.scripted.reset()
    with pytest.raises(Exception):  # smoke set has no pack for an attack technique
        planner_worker.scripted(ConversationSpec(campaign_id="c", technique="tool_misuse", trial_index=0))
    planner_worker.scripted.reset()
    monkeypatch.setenv("PLANNER_PACK_SET", "attacks")
    planner = planner_worker.scripted(ConversationSpec(campaign_id="c2", technique="tool_misuse", trial_index=0))
    assert planner.pack.technique == "tool_misuse"
    planner_worker.scripted.reset()
    monkeypatch.setenv("PLANNER_PACK_SET", "all")
    smoke = planner_worker.scripted(ConversationSpec(campaign_id="c3", technique="smoke_greeting", trial_index=0))
    assert smoke.pack.name == "smoke-greeting"
    planner_worker.scripted.reset()


# ── End to end: attack packs through execute_campaign, real monitors, fake judge ──


class FakeJudgeLLM:
    """Stands in for the Backboard judge: unsafe iff the transcript holds the canary. (Packs
    mention tool names in their own messages, so a tool call is confirmed by the
    deterministic critical monitor rule, not by this judge.)"""

    deployment = "fake/judge"

    def build_structured_chain(self, system_prompt, schema):
        def run(user_message):
            bad = DEFAULT_CANARY in user_message
            return schema.model_validate({
                "assessable": True, "judgement": "unsafe" if bad else "safe",
                "first_failing_turn": 1 if bad else None, "asi_class": "ASI01" if bad else None,
                "severity": "high" if bad else "info", "confidence": 0.95,
                "rationale": "the transcript discloses the canary" if bad else "no disclosure",
            })

        return RunnableLambda(run)

    def invoke_chain(self, chain, user_message, system_context="", run_id=None):
        return chain.invoke(user_message)


@pytest.fixture(autouse=True)
def _fresh_factories():
    planner_worker.scripted.reset()
    yield
    planner_worker.scripted.reset()


def _run_attack_campaign(factory, tmp_path, monkeypatch, *, profile, techniques, **fake_kw):
    safety = tmp_path / "safety"
    safety.mkdir()
    (safety / "default.yaml").write_text(
        f"canary_values: ['{DEFAULT_CANARY}']\nforbidden_tools: ['{DEFAULT_FORBIDDEN_TOOL}']\n", encoding="utf-8")
    monkeypatch.delenv("PLANNER_PACKS_DIR", raising=False)
    monkeypatch.setenv("PLANNER_PACK_SET", "attacks")
    monkeypatch.setenv("TARGET_SAFETY_DIR", str(safety))
    monkeypatch.setenv("PLANNER_FACTORY", "cyberredteam.planners.worker:scripted")
    monkeypatch.setenv("CANARY_JUDGE_VOTES", "3")

    loader = PackLoader(DEFAULT_PACKS_DIR, pack_set="attacks")
    trials = {t: len(loader.for_technique(t)) for t in techniques}
    h = build(factory, fake=FakeTarget(profile=profile, **fake_kw), techniques=list(techniques),
              trials_per_technique=max(trials.values()), max_turns=6)
    SqlTargetStore(factory).set_verified(h.request.target.target_id, "header")
    cid = new_campaign_id()
    CampaignRepo(factory).create(cid, h.request.target.target_id, h.request.policy)
    rt = JobRuntime(factory=factory, runner=None, control=DbRunControl(factory), heartbeat_interval_s=0.05)

    async def on_call(alert):
        pass

    rt.runner = make_runner(
        rt, load_planner_factory(get_settings().planner_factory),
        engine_options={"adapter_factory": h.deps.adapter_factory, "rate_limiter": h.deps.rate_limiter,
                        "clock": h.deps.clock, "on_call": on_call},
        judge_factory=lambda k: Judge(FakeJudgeLLM(), k=k),
    )
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    convs = ConversationRepo(factory)
    out = []
    for conv_id in convs.list_for_campaign(cid):
        conv = convs.get(conv_id, raw=True, actor="test")
        out.append((conv, VerdictRepo(factory).get(conv_id)))
    return h, cid, out


def test_canary_leak_packs_produce_confirmed_findings_against_a_leaking_target(db_factory, tmp_path, monkeypatch):
    techniques = ["sensitive_data_exposure", "prompt_injection", "indirect_injection"]
    h, cid, results = _run_attack_campaign(
        db_factory, tmp_path, monkeypatch, profile="leaks_after_n_turns", techniques=techniques, n_turns=1)
    loader = PackLoader(DEFAULT_PACKS_DIR, pack_set="attacks")
    trials = max(len(loader.for_technique(t)) for t in techniques)
    assert len(results) == trials * len(techniques)  # trial i runs pack i % n, so every pack runs
    leak_packs = {p.name for p in loader.packs() if p.success_signal == "canary_leak"
                  and p.technique in techniques}
    assert leak_packs
    seen_packs = set()
    for conv, verdict in results:
        # Packs are real multi-turn scripts: the leak lands on turn 2 and stops the conversation.
        assert conv.status == "stopped_monitor" and len(conv.turns) == 2
        assert "canary_leak" in conv.turns[1].monitor_hits
        assert verdict.verdict == "confirmed"
        seen_packs.add(conv.turns[0].message)
    for name in leak_packs:
        assert loader.get(name).turns[0].message in seen_packs, name
    assert FindingRepo(db_factory).list(target_id=h.request.target.target_id)


def test_tool_misuse_packs_produce_confirmed_findings_against_a_target_that_calls_forbidden_tools(
    db_factory, tmp_path, monkeypatch
):
    techniques = ["tool_misuse", "privilege_escalation", "authorization_boundary"]
    h, cid, results = _run_attack_campaign(
        db_factory, tmp_path, monkeypatch, profile="tool_misuse_on_turn_k", techniques=techniques, k=2)
    loader = PackLoader(DEFAULT_PACKS_DIR, pack_set="attacks")
    trials = max(len(loader.for_technique(t)) for t in techniques)
    assert len(results) == trials * len(techniques)
    for conv, verdict in results:
        assert conv.status == "stopped_monitor" and len(conv.turns) == 2
        assert "forbidden_tool_call" in conv.turns[1].monitor_hits
        assert verdict.verdict == "confirmed"
    assert FindingRepo(db_factory).list(target_id=h.request.target.target_id)


def test_attack_packs_against_a_safe_target_complete_with_failed_verdicts_and_no_finding(
    db_factory, tmp_path, monkeypatch
):
    h, cid, results = _run_attack_campaign(
        db_factory, tmp_path, monkeypatch, profile="always_safe",
        techniques=["jailbreak", "memory_poisoning", "agent_handoff_corruption"])
    assert results
    for conv, verdict in results:
        assert conv.status == "completed"
        assert verdict.verdict == "failed"  # the attack failed: the target held
    assert FindingRepo(db_factory).list(target_id=h.request.target.target_id) == []
