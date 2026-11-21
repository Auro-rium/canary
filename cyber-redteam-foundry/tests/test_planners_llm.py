# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""WP4 LLMPlanner: stub prompt + fake LLM, fail-closed prompt and classifier,
refusal, length cap, scope, deny categories, provider usage.

No real LLM or network: the model is ``ScriptedStructuredLLM`` or the real
``ChatBackboard`` over ``httpx.MockTransport``. The system prompt is a stub
string; ``prompts/planner.md`` belongs to the security owner and is never
created here. Messages are benign placeholders; deny tests use markers.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging

import httpx
import pytest
from engine_support import _key, build, factory, new_campaign_id  # noqa: F401
from fixtures.fake_llm import FakeStructuredLLM, ScriptedStructuredLLM

from cyberredteam.engine import ConversationState, run_campaign
from cyberredteam.llm.backboard import ChatBackboard
from cyberredteam.llm.observable import ObservableLLM
from cyberredteam.planners import (
    DenyCategoryChecker,
    LLMPlanner,
    PlannerDenyCategory,
    PlannerInvalidOutput,
    PlannerMessageTooLong,
    PlannerPromptMissing,
    PlannerRefused,
    PlannerScopeViolation,
    ScopeClassifierMissing,
    load_planner_prompt,
    make_planner_factory,
)
from cyberredteam.planners.llm_planner import DEFAULT_PROMPT_PATH

STUB_PROMPT = "STUB PLANNER PROMPT FOR TESTS"
STUB_SHA = hashlib.sha256(STUB_PROMPT.encode()).hexdigest()
USAGE = {"input_tokens": 1000, "output_tokens": 200, "total_tokens": 1200}
ALLOW = lambda technique, message: True  # noqa: E731


def _reply(message="benign placeholder turn", **over):
    fields = {"message": message, "intent_note": "placeholder note", "end_conversation": False,
              "refused": False, "refusal_reason": None}
    fields.update(over)
    return fields


def _llm(*replies):
    fake = ScriptedStructuredLLM(list(replies))
    return fake, ObservableLLM(llm=fake, agent_name="planner", deployment="fake/fake")


def _planner(*replies, **kw):
    fake, llm = _llm(*replies)
    kw.setdefault("scope_classifier", ALLOW)
    return fake, LLMPlanner("tech_a", llm=llm, system_prompt=STUB_PROMPT,
                            usd_per_1k_input_tokens=0.01, usd_per_1k_output_tokens=0.03, **kw)


def _state(turns=()):
    return ConversationState(campaign_id="camp", conversation_id="conv-1", technique="tech_a",
                             trial_index=0, turns=list(turns), max_turns=4, remaining_turns=4)


def _events(caplog, name):
    out = []
    for rec in caplog.records:
        try:
            data = json.loads(rec.getMessage())
        except ValueError:
            continue
        if isinstance(data, dict) and data.get("event") == name:
            out.append(data)
    return out


@pytest.fixture
def logs(caplog):
    caplog.set_level(logging.INFO, logger="cyberredteam.planners")
    return caplog


# ── Produces turns ───────────────────────────────────────────────────────────


def test_llm_planner_drives_a_campaign(factory, logs):
    fake, llm = _llm((_reply("placeholder 0"), USAGE), (_reply("placeholder 1"), USAGE),
                     (_reply(end_conversation=True, message=""), USAGE))
    h = build(factory, techniques=["tech_a"], max_turns=5)
    h.deps.planner_factory = make_planner_factory(
        "llm", llm=llm, system_prompt=STUB_PROMPT, scope_classifier=ALLOW)
    outcome = asyncio.run(run_campaign(h.request, new_campaign_id(), h.deps))
    conv = h.conversations.get(outcome.conversations[0].conversation_id, raw=True, actor="test")
    assert conv.status == "completed"
    assert [t.message for t in conv.turns] == ["placeholder 0", "placeholder 1"]
    assert fake.calls == 3
    # The model saw the transcript (including the target's reply) as JSON data.
    last_prompt = fake.prompts[-1].to_messages()[-1].content
    assert json.loads(last_prompt)["transcript"][1]["message"] == "placeholder 1"
    # Spend is charged from provider usage: 3 calls x 1200 tokens.
    assert outcome.llm_cost_usd == pytest.approx(3 * (1000 * 0.01 + 200 * 0.03) / 1000, rel=1e-6)
    turns = _events(logs, "planner_turn")
    assert len(turns) == 3 and {e["prompt_sha256"] for e in turns} == {STUB_SHA}


def test_prompt_version_on_planned_turn(logs):
    _, p = _planner((_reply(), USAGE))
    turn = asyncio.run(p.next_turn(_state()))
    assert p.prompt_version == STUB_SHA
    assert turn.intent_note.startswith(f"[planner_prompt_sha256={STUB_SHA}]")
    assert "placeholder note" in turn.intent_note


# ── Fail closed at construction ──────────────────────────────────────────────


def test_shipped_repo_has_no_planner_prompt_and_fails_closed():
    assert not DEFAULT_PROMPT_PATH.exists()  # owned by the security owner, not shipped
    with pytest.raises(PlannerPromptMissing, match="security owner"):
        load_planner_prompt()
    with pytest.raises(PlannerPromptMissing):
        LLMPlanner("tech_a", scope_classifier=ALLOW, llm=_llm((_reply(), None))[1])
    with pytest.raises(PlannerPromptMissing):
        make_planner_factory("llm", scope_classifier=ALLOW)


def test_missing_or_empty_prompt_file_fails_closed(tmp_path):
    with pytest.raises(PlannerPromptMissing, match="missing"):
        load_planner_prompt(tmp_path / "planner.md")
    empty = tmp_path / "empty.md"
    empty.write_text("  \n\t", encoding="utf-8")
    with pytest.raises(PlannerPromptMissing, match="empty"):
        make_planner_factory("llm", prompt_path=empty, scope_classifier=ALLOW)
    with pytest.raises(PlannerPromptMissing):
        LLMPlanner("tech_a", scope_classifier=ALLOW, system_prompt="")
    good = tmp_path / "ok.md"
    good.write_text(STUB_PROMPT, encoding="utf-8")
    assert load_planner_prompt(good).sha256 == STUB_SHA


def test_prompt_path_setting(tmp_path, monkeypatch):
    path = tmp_path / "p.md"
    path.write_text(STUB_PROMPT, encoding="utf-8")
    monkeypatch.setenv("PLANNER_PROMPT_PATH", str(path))
    assert load_planner_prompt().sha256 == STUB_SHA


def test_missing_scope_classifier_refuses_to_run():
    with pytest.raises(ScopeClassifierMissing):
        LLMPlanner("tech_a", scope_classifier=None, system_prompt=STUB_PROMPT,
                   llm=_llm((_reply(), None))[1])
    with pytest.raises(ScopeClassifierMissing):
        make_planner_factory("llm", system_prompt=STUB_PROMPT, llm=_llm((_reply(), None))[1])


# ── Guard rails ──────────────────────────────────────────────────────────────


def test_structural_refusal_ends_conversation_as_planner_refused(factory, logs):
    fake, llm = _llm((_reply("placeholder 0"), USAGE),
                     (_reply("", refused=True, refusal_reason="policy_category"), USAGE))
    h = build(factory, techniques=["tech_a"], max_turns=5)
    h.deps.planner_factory = make_planner_factory(
        "llm", llm=llm, system_prompt=STUB_PROMPT, scope_classifier=ALLOW)
    outcome = asyncio.run(run_campaign(h.request, new_campaign_id(), h.deps))
    conv = h.conversations.get(outcome.conversations[0].conversation_id, raw=True, actor="test")
    assert conv.status == "error"  # never "completed": a refusal is not a safe result
    assert len(conv.turns) == 1 and len(h.fake.requests) == 1
    refused = _events(logs, "planner_refused")
    assert len(refused) == 1
    assert refused[0]["detail"] == "structural" and refused[0]["prompt_sha256"] == STUB_SHA
    assert refused[0]["conversation_id"] == conv.conversation_id


@pytest.mark.parametrize("reply", [
    _reply("I'm sorry, but I can't help with that."),
    _reply("I cannot assist with this request."),
    _reply("As an AI, I will not do this."),
    _reply("", end_conversation=True, intent_note="I won't help with this request"),
])
def test_refusal_text_is_detected(reply, logs):
    _, p = _planner((reply, USAGE))
    with pytest.raises(PlannerRefused) as err:
        asyncio.run(p.next_turn(_state()))
    assert err.value.reason == "planner_refused" and err.value.detail == "refusal_text"
    # The spend of the refused call travels on the exception.
    assert err.value.llm_tokens == 1200 and err.value.llm_cost_usd > 0
    assert _events(logs, "planner_refused")


def test_length_cap_rejects_not_truncates():
    _, p = _planner((_reply("a" * 51), USAGE), max_message_chars=50)
    with pytest.raises(PlannerMessageTooLong, match="length=51 cap=50"):
        asyncio.run(p.next_turn(_state()))
    _, ok = _planner((_reply("a" * 50), USAGE), max_message_chars=50)
    assert asyncio.run(ok.next_turn(_state())).message == "a" * 50


def test_default_length_cap_is_4000():
    _, p = _planner((_reply("a" * 4001), USAGE))
    assert p.guards.max_message_chars == 4000
    with pytest.raises(PlannerMessageTooLong):
        asyncio.run(p.next_turn(_state()))


def test_scope_classifier_denial(logs):
    calls = []

    def deny(technique, message):
        calls.append((technique, message))
        return False

    _, p = _planner((_reply(), USAGE), scope_classifier=deny)
    with pytest.raises(PlannerScopeViolation):
        asyncio.run(p.next_turn(_state()))
    assert calls == [("tech_a", "benign placeholder turn")]
    assert _events(logs, "planner_out_of_scope")[0]["detail"] == "classifier_denied"


def test_scope_classifier_must_return_true_exactly():
    _, p = _planner((_reply(), USAGE), scope_classifier=lambda t, m: "yes")
    with pytest.raises(PlannerScopeViolation):
        asyncio.run(p.next_turn(_state()))


def test_deny_category_ends_conversation(logs):
    checker = DenyCategoryChecker({"category_a": [r"<<deny:category_a>>"]})
    scope_calls = []
    _, p = _planner((_reply("text <<deny:category_a>> text"), USAGE), deny_checker=checker,
                    scope_classifier=lambda t, m: scope_calls.append(m) or True)
    with pytest.raises(PlannerDenyCategory, match="category=category_a"):
        asyncio.run(p.next_turn(_state()))
    assert scope_calls == []  # deny check runs before the classifier
    event = _events(logs, "planner_deny_category")[0]
    assert "<<deny" not in json.dumps(event)  # message text never logged


def test_empty_message_without_end_is_invalid():
    _, p = _planner((_reply("   "), USAGE))
    with pytest.raises(PlannerInvalidOutput):
        asyncio.run(p.next_turn(_state()))


# ── Usage comes from the provider ────────────────────────────────────────────


def test_usage_from_provider_metadata():
    _, p = _planner((_reply(), {"input_tokens": 300, "output_tokens": 50, "total_tokens": 400}))
    turn = asyncio.run(p.next_turn(_state()))
    assert turn.llm_tokens == 400
    # 50 unattributed tokens are priced at the output rate.
    assert turn.llm_cost_usd == pytest.approx((300 * 0.01 + 100 * 0.03) / 1000)


def test_usage_estimated_conservatively_without_provider_usage(logs):
    llm = ObservableLLM(llm=FakeStructuredLLM(), agent_name="planner", deployment="fake")
    p = LLMPlanner("tech_a", llm=llm, system_prompt=STUB_PROMPT, scope_classifier=ALLOW)
    turn = asyncio.run(p.next_turn(_state()))
    assert turn.llm_tokens >= len(STUB_PROMPT) // 3 and turn.llm_cost_usd > 0
    assert _events(logs, "planner_turn")[0]["usage_estimated"] is True


def _backboard(content: str, usage: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": content, "status": "COMPLETED", **usage})

    chat = ChatBackboard(api_key="test-key", base_url="https://backboard.invalid/api",
                         transport=httpx.MockTransport(handler))
    return ObservableLLM(llm=chat, agent_name="planner", deployment="openai/test")


def test_backboard_usage_is_used_and_model_cannot_set_it():
    usage = {"input_tokens": 700, "output_tokens": 100, "total_tokens": 800}
    honest = json.dumps(_reply("placeholder via backboard"))
    p = LLMPlanner("tech_a", llm=_backboard(honest, usage), system_prompt=STUB_PROMPT,
                   scope_classifier=ALLOW, usd_per_1k_input_tokens=0.01, usd_per_1k_output_tokens=0.03)
    turn = asyncio.run(p.next_turn(_state()))
    assert turn.message == "placeholder via backboard"
    assert turn.llm_tokens == 800
    assert turn.llm_cost_usd == pytest.approx((700 * 0.01 + 100 * 0.03) / 1000)

    # A reply that tries to report its own (zero) usage is rejected outright:
    # PlannerOutput has no usage fields and forbids unknown ones.
    smuggled = json.dumps({**_reply(), "llm_tokens": 0, "llm_cost_usd": 0.0})
    p2 = LLMPlanner("tech_a", llm=_backboard(smuggled, usage), system_prompt=STUB_PROMPT,
                    scope_classifier=ALLOW)
    with pytest.raises(ValueError):
        asyncio.run(p2.next_turn(_state()))
