"""WP0 contract tests: validation rules and JSON round-trips for contracts.py."""

import json
import uuid

import pytest
from pydantic import ValidationError

from cyberredteam.contracts import (
    SSE_EVENT_TYPES,
    BearerAuth,
    CampaignCancelledEvent,
    CampaignCancelledPayload,
    CampaignPolicy,
    Conversation,
    ConversationVerdict,
    CookieLoginAuth,
    HeaderAuth,
    JudgeVote,
    NoAuth,
    OAuthClientCredentialsAuth,
    TargetConfig,
    TechniqueResult,
    ToolCallObservation,
    Turn,
    TurnEvent,
    normalize_asi_code,
    parse_sse_event,
    validate_policy_for_target,
    wilson_interval,
)

TID = str(uuid.uuid4())


def _target(**overrides):
    data = {
        "target_id": TID,
        "name": "staging agent",
        "endpoint": "https://agent.example.test/chat",
        "session_mode": "stateless_history",
        "environment": "staging",
    }
    data.update(overrides)
    return TargetConfig.model_validate(data)


def _turn(i, cid="c1", **kw):
    data = dict(conversation_id=cid, index=i, message=f"m{i}", response_text=f"r{i}", latency_ms=12.5)
    data.update(kw)
    return Turn(**data)


# ── TargetConfig ─────────────────────────────────────────────────────────────


def test_target_defaults():
    t = _target()
    assert t.method == "POST"
    assert isinstance(t.auth, NoAuth)
    assert t.streaming == "none"
    assert t.timeout_s == 60
    assert t.verified is False


def test_target_id_must_be_uuid():
    with pytest.raises(ValidationError):
        _target(target_id="not-a-uuid")


def test_target_environment_required():
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(
            {"target_id": TID, "name": "x", "endpoint": "https://a.test", "session_mode": "cookie"}
        )


def test_target_forbids_unknown_fields():
    with pytest.raises(ValidationError):
        _target(surprise=True)


def test_server_session_requires_session_id_path():
    with pytest.raises(ValidationError, match="session_id_path"):
        _target(session_mode="server_session")
    assert _target(session_mode="server_session", session_id_path="data.session_id")


@pytest.mark.parametrize(
    "template",
    [
        '{"message": "{{MESSAGE}}"}',
        '{"input": {"text": "{{MESSAGE}}"}, "history": "{{HISTORY}}"}',
    ],
)
def test_request_template_valid(template):
    assert _target(request_template=template).request_template == template


def test_request_template_with_session_id():
    tpl = '{"message": "{{MESSAGE}}", "session_id": "{{SESSION_ID}}"}'
    t = _target(request_template=tpl, session_mode="server_session", session_id_path="sid")
    assert t.request_template == tpl
    with pytest.raises(ValidationError, match="SESSION_ID"):
        _target(request_template=tpl)  # stateless mode


@pytest.mark.parametrize(
    "template,reason",
    [
        ('{"message": {{MESSAGE}}}', "quoted"),  # unquoted placeholder
        ('{"message": "hello"}', "quoted"),  # missing placeholder
        ('{"message": "{{PROMPT}}"}', "unknown placeholder"),  # legacy placeholder
        ('{"message": "{{MESSAGE}}",}', "not valid JSON"),
        ('{"message": "{{MESSAGE}}", "h": {{HISTORY}}}', "quoted"),
    ],
)
def test_request_template_invalid(template, reason):
    with pytest.raises(ValidationError, match=reason):
        _target(request_template=template)


def test_dot_paths_validated():
    assert _target(response_path="choices.0.message.content").response_path
    with pytest.raises(ValidationError):
        _target(response_path="choices[0].content")


# ── TargetAuth ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "auth,cls,secret_field",
    [
        ({"type": "none"}, NoAuth, None),
        ({"type": "bearer", "token": "tok-123"}, BearerAuth, "token"),
        ({"type": "header", "header_name": "X-Api-Key", "value": "v-123"}, HeaderAuth, "value"),
        (
            {
                "type": "oauth_client_credentials",
                "token_url": "https://idp.example.test/token",
                "client_id": "canary",
                "client_secret": "cs-123",
                "scope": "chat",
            },
            OAuthClientCredentialsAuth,
            "client_secret",
        ),
        (
            {
                "type": "cookie_login",
                "login_url": "https://agent.example.test/login",
                "username": "tester",
                "password": "pw-123",
            },
            CookieLoginAuth,
            "password",
        ),
    ],
)
def test_auth_discriminated_union_and_secret_masking(auth, cls, secret_field):
    t = _target(auth=auth)
    assert isinstance(t.auth, cls)
    if secret_field:
        raw = auth[secret_field]
        assert getattr(t.auth, secret_field).get_secret_value() == raw
        dumped = t.model_dump_json()
        assert raw not in dumped
        assert "**********" in dumped
        assert raw not in repr(t)


def test_auth_unknown_type_rejected():
    with pytest.raises(ValidationError):
        _target(auth={"type": "basic", "user": "u"})


@pytest.mark.parametrize("name", ["Host", "content-type", "X-Canary-Campaign", "Bad Header"])
def test_header_auth_rejects_reserved_or_invalid_names(name):
    with pytest.raises(ValidationError):
        HeaderAuth(header_name=name, value="v")


# ── CampaignPolicy ───────────────────────────────────────────────────────────


def test_policy_defaults_valid_for_staging():
    p = CampaignPolicy(techniques=["prompt_injection"])
    assert (p.trials_per_technique, p.max_turns, p.max_parallel_conversations) == (5, 8, 4)
    assert validate_policy_for_target(p, _target()) == p


def test_policy_requires_techniques_unique_nonempty():
    for bad in ([], ["a", "a"], [" "]):
        with pytest.raises(ValidationError):
            CampaignPolicy(techniques=bad)


def test_default_policy_is_rejected_in_production():
    """Defaults (parallel 4, total 500) exceed section-4 production limits."""
    p = CampaignPolicy(techniques=["prompt_injection"])
    with pytest.raises(ValidationError) as exc:
        validate_policy_for_target(p, _target(environment="production"))
    msg = str(exc.value)
    assert "max_parallel_conversations" in msg and "max_total_requests" in msg


def _prod_ok(**kw):
    data = dict(
        techniques=["prompt_injection"],
        rate_limit_rps=1.0,
        max_parallel_conversations=2,
        max_total_requests=300,
    )
    data.update(kw)
    return data


def test_production_policy_at_limits_accepted():
    p = CampaignPolicy.model_validate(_prod_ok(), context={"environment": "production"})
    assert p.max_total_requests == 300


@pytest.mark.parametrize(
    "override,needle",
    [
        ({"allow_destructive_tools": True}, "allow_destructive_tools"),
        ({"rate_limit_rps": 1.5}, "rate_limit_rps"),
        ({"max_parallel_conversations": 3}, "max_parallel_conversations"),
        ({"max_total_requests": 301}, "max_total_requests"),
        ({"techniques": ["workflow_manipulation"]}, "staging-only"),
        ({"techniques": ["denial-of-service"]}, "staging-only"),
    ],
)
def test_production_policy_violations_rejected(override, needle):
    data = _prod_ok(**override)
    with pytest.raises(ValidationError, match=needle):
        CampaignPolicy.model_validate(data, context={"environment": "production"})
    # Same policy is fine in staging.
    CampaignPolicy.model_validate(data, context={"environment": "staging"})


def test_policy_bounds():
    with pytest.raises(ValidationError):
        CampaignPolicy(techniques=["x"], rate_limit_rps=0)
    with pytest.raises(ValidationError):
        CampaignPolicy(techniques=["x"], max_turns=0)


# ── ASI codes ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("code", [f"ASI{i:02d}" for i in range(1, 11)])
def test_asi_regex_accepts_canonical(code):
    v = _verdict(asi_class=code)
    assert v.asi_class == code


@pytest.mark.parametrize("code", ["ASI-01", "ASI1", "ASI00", "ASI11", "asi01", "ASI010", ""])
def test_asi_regex_rejects_non_canonical(code):
    with pytest.raises(ValidationError):
        _verdict(asi_class=code)


@pytest.mark.parametrize(
    "raw,expected",
    [("ASI01", "ASI01"), ("ASI-01", "ASI01"), ("asi_9", "ASI09"), (" ASI 10 ", "ASI10"), (None, None), ("", None)],
)
def test_normalize_asi_code(raw, expected):
    assert normalize_asi_code(raw) == expected


@pytest.mark.parametrize("raw", ["ASI-11", "ASI-00", "LLM01", "ASI"])
def test_normalize_asi_code_rejects(raw):
    with pytest.raises(ValueError):
        normalize_asi_code(raw)


# ── Turn / Conversation ──────────────────────────────────────────────────────


def test_turn_defaults_and_tool_calls():
    t = _turn(0, tool_calls=[{"name": "lookup_order", "arguments": {"id": "1"}}])
    assert t.role_sent == "user"
    assert t.tool_calls[0] == ToolCallObservation(name="lookup_order", arguments={"id": "1"})
    assert t.tool_calls[0].source == "structured"
    assert _turn(0).tool_calls == [] and _turn(0).monitor_hits == []


def test_turn_rejects_bad_values():
    with pytest.raises(ValidationError):
        _turn(-1)
    with pytest.raises(ValidationError):
        _turn(0, http_status=99)
    with pytest.raises(ValidationError):
        _turn(0, latency_ms=-1)


def test_conversation_turn_consistency():
    conv = Conversation(
        conversation_id="c1", campaign_id="k1", technique="prompt_injection", trial_index=0,
        turns=[_turn(0), _turn(1)],
    )
    assert conv.status == "running" and len(conv.turns) == 2
    with pytest.raises(ValidationError, match="contiguous"):
        Conversation(conversation_id="c1", campaign_id="k", technique="t", trial_index=0,
                     turns=[_turn(0), _turn(2)])
    with pytest.raises(ValidationError, match="another conversation"):
        Conversation(conversation_id="c1", campaign_id="k", technique="t", trial_index=0,
                     turns=[_turn(0, cid="c2")])
    with pytest.raises(ValidationError):
        Conversation(conversation_id="c1", campaign_id="k", technique="t", trial_index=0,
                     status="paused")


# ── Verdicts / votes / technique results ─────────────────────────────────────


def _verdict(**kw):
    data = dict(
        conversation_id="c1", verdict="confirmed", first_failing_turn=2,
        deterministic_hits=["CANARY_VALUE"],
        judge_votes=[JudgeVote(vote_index=i, judgement="unsafe", confidence=0.9) for i in range(3)],
        judge_agreement=1.0, severity="critical", asi_class="ASI04", rationale="r",
    )
    data.update(kw)
    return ConversationVerdict(**data)


def test_judge_vote_temperature_is_zero():
    assert JudgeVote(vote_index=0, judgement="safe", confidence=0.5).temperature == 0.0
    with pytest.raises(ValidationError):
        JudgeVote(vote_index=0, judgement="safe", confidence=0.5, temperature=0.7)


def test_verdict_agreement_bounds():
    with pytest.raises(ValidationError):
        _verdict(judge_agreement=1.5)
    with pytest.raises(ValidationError):
        _verdict(verdict="vulnerable")


def test_wilson_interval_known_values():
    low, high = wilson_interval(5, 10)
    assert low == pytest.approx(0.2366, abs=1e-3) and high == pytest.approx(0.7634, abs=1e-3)
    assert wilson_interval(0, 0) == (0.0, 1.0)
    low, high = wilson_interval(0, 20)
    assert low == 0.0 and high == pytest.approx(0.1611, abs=1e-3)


def test_technique_result_from_counts_and_consistency():
    r = TechniqueResult.from_counts("prompt_injection", 20, 3)
    assert r.success_rate == pytest.approx(0.15)
    assert r.ci95_low < r.success_rate < r.ci95_high
    assert TechniqueResult.from_counts("t", 0, 0).success_rate == 0.0
    with pytest.raises(ValidationError):
        TechniqueResult(technique="t", trials=2, confirmed=3, success_rate=1, ci95_low=0, ci95_high=1)
    with pytest.raises(ValidationError):
        TechniqueResult(technique="t", trials=4, confirmed=2, success_rate=0.5, ci95_low=0.6, ci95_high=0.9)


# ── SSE v2 envelope ──────────────────────────────────────────────────────────


def _sample_events():
    return [
        {"type": "campaign_started", "seq": 0, "payload": {
            "campaign_id": "k", "target_id": TID, "environment": "staging",
            "techniques": ["prompt_injection"], "trials_per_technique": 5, "total_conversations": 5}},
        {"type": "conversation_started", "seq": 1, "payload": {
            "campaign_id": "k", "conversation_id": "c1", "technique": "prompt_injection", "trial_index": 0}},
        {"type": "turn", "seq": 2, "payload": {
            "campaign_id": "k", "conversation_id": "c1", "index": 0, "message_preview": "hi",
            "response_preview": "hello", "latency_ms": 3.0, "http_status": 200}},
        {"type": "monitor_hit", "seq": 3, "payload": {
            "campaign_id": "k", "conversation_id": "c1", "turn_index": 0, "hit": "CANARY_VALUE",
            "severity": "critical", "stops_conversation": True}},
        {"type": "conversation_finished", "seq": 4, "payload": {
            "campaign_id": "k", "conversation_id": "c1", "status": "stopped_monitor", "turns": 1}},
        {"type": "verdict", "seq": 5, "payload": {
            "campaign_id": "k", "verdict": _verdict().model_dump(mode="json")}},
        {"type": "budget_update", "seq": 6, "payload": {
            "campaign_id": "k", "requests_used": 1, "max_total_requests": 300,
            "llm_cost_usd": 0.01, "max_llm_cost_usd": 10}},
        {"type": "campaign_complete", "seq": 7, "payload": {
            "campaign_id": "k", "conversations": 1, "confirmed": 1, "duration_seconds": 1.5,
            "technique_results": [TechniqueResult.from_counts("prompt_injection", 1, 1).model_dump()]}},
        {"type": "campaign_failed", "seq": 8, "payload": {"campaign_id": "k", "message": "boom"}},
        {"type": "campaign_cancelled", "seq": 9, "payload": {"campaign_id": "k", "reason": "kill_switch"}},
    ]


def test_sse_samples_cover_every_event_type():
    assert [e["type"] for e in _sample_events()] == list(SSE_EVENT_TYPES)


@pytest.mark.parametrize("raw", _sample_events(), ids=lambda e: e["type"])
def test_sse_event_parse_and_json_round_trip(raw):
    event = parse_sse_event(raw)
    assert event.type == raw["type"]
    assert event.timestamp.tzinfo is not None
    again = parse_sse_event(event.model_dump_json())
    assert again == event
    wire = event.to_sse()
    assert wire.startswith(f"id: {raw['seq']}\ndata: ") and wire.endswith("\n\n")
    body = json.loads(wire.split("data: ", 1)[1])
    assert set(body) == {"type", "payload", "timestamp", "seq"}


def test_sse_rejects_unknown_type_and_mismatched_payload():
    with pytest.raises(ValidationError):
        parse_sse_event({"type": "log", "seq": 0, "payload": {"message": "x"}})
    with pytest.raises(ValidationError):
        parse_sse_event({"type": "turn", "seq": 0, "payload": {"campaign_id": "k", "message": "x"}})
    with pytest.raises(ValidationError):
        CampaignCancelledEvent(seq=-1, payload=CampaignCancelledPayload(campaign_id="k"))


def test_turn_event_preview_is_capped():
    with pytest.raises(ValidationError):
        TurnEvent(seq=0, payload={
            "campaign_id": "k", "conversation_id": "c", "index": 0, "message_preview": "x" * 281,
            "response_preview": "", "latency_ms": 0})


# ── JSON round-trips for the data models ─────────────────────────────────────


@pytest.mark.parametrize(
    "model",
    [
        CampaignPolicy(techniques=["prompt_injection", "tool_misuse"], stop_on_first_confirmed=True),
        Conversation(conversation_id="c1", campaign_id="k", technique="t", trial_index=3,
                     status="completed", turns=[_turn(0, tool_calls=[{"name": "x", "source": "heuristic"}])],
                     target_session_ref="sess-1"),
        _verdict(),
        TechniqueResult.from_counts("t", 7, 2),
        _target(response_path="reply", tool_trace_path="tool_calls", streaming="sse"),
    ],
    ids=lambda m: type(m).__name__,
)
def test_json_round_trip(model):
    restored = type(model).model_validate_json(model.model_dump_json())
    assert restored == model


def test_target_round_trip_masks_secrets():
    t = _target(auth={"type": "bearer", "token": "tok-123"})
    data = json.loads(t.model_dump_json())
    assert data["auth"] == {"type": "bearer", "token": "**********"}
    restored = TargetConfig.model_validate(data)
    # Secrets never round-trip: the restored token is the mask, not the value.
    assert restored.auth.token.get_secret_value() == "**********"
    assert restored.model_dump(exclude={"auth"}) == t.model_dump(exclude={"auth"})
