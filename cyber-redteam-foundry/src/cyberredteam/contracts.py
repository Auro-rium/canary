"""Frozen v2 contracts for the multi-turn platform (WP0).

These models are the shared language between the conversation engine, the
session adapter, the evaluator, the data layer, the API and the UI. They are
mirrored one-to-one in ``canary/src/lib/contracts.ts``. Changing a model here
means changing ``docs/plan/multiturn-build-plan.md`` section 2 and the
TypeScript mirror in the same commit.

The legacy single-turn models in ``schemas.py`` are untouched.

Conventions
-----------
* Every model forbids unknown fields (``extra="forbid"``) so contract drift
  fails loudly instead of being silently dropped.
* ASI classes use the canonical ``ASI01``..``ASI10`` form everywhere.
* Secrets are ``SecretStr``: they serialise as ``"**********"`` and are only
  readable through ``get_secret_value()``. Contracts never round-trip a secret.
* Production safety (plan section 4) is enforced by rejecting, never by
  silently clamping: see :func:`validate_policy_for_target`.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Union

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    SecretStr,
    StringConstraints,
    TypeAdapter,
    ValidationInfo,
    field_validator,
    model_validator,
)

# ── Shared primitives ─────────────────────────────────────────────────────────

ASI_CODE_PATTERN = r"^ASI(0[1-9]|10)$"
AsiCode = Annotated[str, StringConstraints(pattern=ASI_CODE_PATTERN)]

_LEGACY_ASI_RE = re.compile(r"^\s*ASI[\s_-]*0*([1-9]|10)\s*$", re.IGNORECASE)


def normalize_asi_code(value: str | None) -> str | None:
    """Return the canonical ``ASI01`` form of a legacy or loose ASI code.

    Accepts ``ASI01``, ``ASI-01``, ``asi_1``, ``ASI 10`` and so on. Returns
    ``None`` for empty input. Raises ``ValueError`` for anything that is not an
    ASI class 1..10, so bad data is never silently relabelled.
    """
    if value is None or not str(value).strip():
        return None
    match = _LEGACY_ASI_RE.match(str(value))
    if not match:
        raise ValueError(f"not an ASI class code: {value!r}")
    return f"ASI{int(match.group(1)):02d}"


Severity = Literal["info", "low", "medium", "high", "critical"]
Environment = Literal["staging", "production"]
SessionMode = Literal["stateless_history", "server_session", "cookie"]
StreamingMode = Literal["none", "sse", "ndjson"]

# RFC 7230 token characters for HTTP header names.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# Headers the adapter owns; operator auth must not override them.
RESERVED_HEADERS = frozenset(
    {"host", "content-length", "content-type", "transfer-encoding", "x-canary-campaign"}
)


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


SECRET_MASK = "**********"


def _reject_mask(v: SecretStr) -> SecretStr:
    value = v.get_secret_value()
    if value == SECRET_MASK:
        raise ValueError(
            f"secret is the redaction mask {SECRET_MASK!r}, not a real value; "
            "send the actual secret"
        )
    if not value:
        raise ValueError("secret must not be empty")
    return v


# A SecretStr that refuses the mask, so a dumped-and-reloaded config can never
# silently store "**********" as a credential. (WP1 adds keep-existing
# semantics for updates.)
Secret = Annotated[SecretStr, AfterValidator(_reject_mask)]


# ── Target auth (discriminated on ``type``) ──────────────────────────────────


class NoAuth(_Contract):
    type: Literal["none"] = "none"


class BearerAuth(_Contract):
    type: Literal["bearer"] = "bearer"
    token: Secret


class HeaderAuth(_Contract):
    """A custom header, e.g. ``X-Api-Key: <value>``."""

    type: Literal["header"] = "header"
    header_name: str
    value: Secret

    @field_validator("header_name")
    @classmethod
    def _valid_header_name(cls, v: str) -> str:
        if not _HEADER_NAME_RE.match(v):
            raise ValueError("header_name must be a valid HTTP header token")
        if v.lower() in RESERVED_HEADERS:
            raise ValueError(f"header_name {v!r} is reserved by the adapter")
        return v


class OAuthClientCredentialsAuth(_Contract):
    """OAuth 2.0 client-credentials grant; the adapter refreshes on expiry."""

    type: Literal["oauth_client_credentials"] = "oauth_client_credentials"
    token_url: HttpUrl
    client_id: str = Field(min_length=1)
    client_secret: Secret
    scope: str | None = None
    audience: str | None = None


class CookieLoginAuth(_Contract):
    """Form/JSON login that sets a session cookie, reused for the conversation."""

    type: Literal["cookie_login"] = "cookie_login"
    login_url: HttpUrl
    username: str = Field(min_length=1)
    password: Secret
    username_field: str = "username"
    password_field: str = "password"


TargetAuth = Annotated[
    Union[NoAuth, BearerAuth, HeaderAuth, OAuthClientCredentialsAuth, CookieLoginAuth],
    Field(discriminator="type"),
]


# ── Target ────────────────────────────────────────────────────────────────────

TEMPLATE_PLACEHOLDERS = ("{{MESSAGE}}", "{{SESSION_ID}}", "{{HISTORY}}")
_TOKEN_RE = re.compile(r"\{\{[^{}]*\}\}")


def validate_request_template(template: str) -> str:
    """Validate a request template.

    Rules: every ``{{...}}`` token is exactly one of ``TEMPLATE_PLACEHOLDERS``
    (no inner whitespace; unknown names such as the legacy ``{{PROMPT}}`` are
    rejected); the template is valid JSON; a placeholder is only ever a whole
    JSON string *value*, never a key and never part of a longer string;
    ``"{{MESSAGE}}"`` appears exactly once and the optional
    ``"{{SESSION_ID}}"`` / ``"{{HISTORY}}"`` at most once each. Each quoted placeholder is
    replaced whole by ``json.dumps(value)`` at render time (``{{HISTORY}}``
    becomes an OpenAI-style messages array), which is why the raw template
    stays parseable JSON.
    """
    for token in _TOKEN_RE.findall(template):
        if token not in TEMPLATE_PLACEHOLDERS:
            raise ValueError(f"unknown placeholder {token}; allowed: {', '.join(TEMPLATE_PLACEHOLDERS)}")
    for token in TEMPLATE_PLACEHOLDERS:
        if template.count(token) != template.count(f'"{token}"'):
            raise ValueError(f'placeholder {token} must appear as a quoted JSON string "{token}"')
    try:
        parsed = json.loads(template)
    except json.JSONDecodeError as exc:
        raise ValueError(f"request_template is not valid JSON: {exc.msg}") from exc

    counts = dict.fromkeys(TEMPLATE_PLACEHOLDERS, 0)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if _TOKEN_RE.search(key):
                    raise ValueError("placeholders are not allowed in JSON keys")
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, str) and _TOKEN_RE.search(node):
            if node not in counts:
                raise ValueError("a placeholder must be the whole quoted JSON string value")
            counts[node] += 1

    walk(parsed)
    if counts["{{MESSAGE}}"] != 1:
        raise ValueError(
            'request_template must contain the quoted "{{MESSAGE}}" placeholder exactly once'
        )
    for token in ("{{SESSION_ID}}", "{{HISTORY}}"):
        if counts[token] > 1:
            raise ValueError(f"placeholder {token} may appear at most once")
    return template


_DOT_PATH_RE = re.compile(r"^[A-Za-z0-9_\-]+(\.[A-Za-z0-9_\-]+)*$")


def _check_dot_path(v: str | None) -> str | None:
    if v is not None and not _DOT_PATH_RE.match(v):
        raise ValueError("must be a dot path such as 'choices.0.message.content'")
    return v


class TargetConfig(_Contract):
    target_id: str
    name: str = Field(min_length=1, max_length=200)
    endpoint: HttpUrl
    method: Literal["POST"] = "POST"
    auth: TargetAuth = Field(default_factory=NoAuth)
    request_template: str | None = None
    response_path: str | None = None
    session_mode: SessionMode
    session_id_path: str | None = None
    tool_trace_path: str | None = None
    streaming: StreamingMode = "none"
    timeout_s: int = Field(default=60, ge=1, le=600)
    verified: bool = False
    environment: Environment

    @field_validator("target_id")
    @classmethod
    def _uuid(cls, v: str) -> str:
        try:
            return str(uuid.UUID(v))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("target_id must be a UUID") from exc

    @field_validator("request_template")
    @classmethod
    def _template(cls, v: str | None) -> str | None:
        return validate_request_template(v) if v is not None else None

    @field_validator("response_path", "session_id_path", "tool_trace_path")
    @classmethod
    def _paths(cls, v: str | None) -> str | None:
        return _check_dot_path(v)

    @model_validator(mode="after")
    def _session_requirements(self) -> "TargetConfig":
        if self.session_mode == "server_session" and not self.session_id_path:
            raise ValueError("session_mode='server_session' requires session_id_path")
        if self.request_template and "{{SESSION_ID}}" in self.request_template:
            if self.session_mode != "server_session":
                raise ValueError("{{SESSION_ID}} is only valid with session_mode='server_session'")
        return self


# ── Campaign policy ──────────────────────────────────────────────────────────

PRODUCTION_LIMITS: dict[str, float] = {
    "rate_limit_rps": 1.0,
    "max_parallel_conversations": 2,
    "max_total_requests": 300,
}
# Resource-exhaustion techniques are staging-only (plan section 4). Both the
# backend strategy name and the UI slug are listed.
PRODUCTION_FORBIDDEN_TECHNIQUES = frozenset({"workflow_manipulation", "denial-of-service"})


def normalize_technique(name: str) -> str:
    """Canonical technique key for comparisons: stripped and casefolded."""
    return name.strip().casefold()


class CampaignPolicy(_Contract):
    """Budgets and limits for one campaign.

    Production rules need the target's environment, which is not part of the
    policy, so a bare ``CampaignPolicy`` does NOT enforce them. Campaign
    creation must validate through :class:`CampaignRequest`, which always does.
    The context form (``context={"environment": ...}``) and
    :func:`validate_policy_for_target` exist for callers that already hold
    both halves. Violations are rejected, never clamped.
    """

    techniques: list[str] = Field(min_length=1, max_length=100)
    trials_per_technique: int = Field(default=5, ge=1, le=1000)
    max_turns: int = Field(default=8, ge=1, le=100)
    max_parallel_conversations: int = Field(default=4, ge=1, le=64)
    rate_limit_rps: float = Field(default=1.0, gt=0, le=100)
    max_total_requests: int = Field(default=500, ge=1, le=1_000_000)
    max_llm_cost_usd: float = Field(default=10.0, ge=0, le=10_000)
    stop_on_first_confirmed: bool = False
    allow_destructive_tools: bool = False

    @field_validator("techniques")
    @classmethod
    def _techniques(cls, v: list[str]) -> list[str]:
        if any(not t.strip() for t in v):
            raise ValueError("technique names must be non-empty")
        if len({normalize_technique(t) for t in v}) != len(v):
            raise ValueError("techniques must be unique (ignoring case and surrounding spaces)")
        return v

    def production_violations(self) -> list[str]:
        """Return human-readable section-4 violations (empty if compliant).

        Fail closed even on an unvalidated instance (``model_construct``):
        each limit must be a finite number with ``0 < value <= limit`` (NaN,
        infinities, zero/negative values and non-numbers are violations), and
        ``allow_destructive_tools`` must be exactly ``False``.
        """
        problems: list[str] = []
        if getattr(self, "allow_destructive_tools", True) is not False:
            problems.append("allow_destructive_tools must be false in production")
        for name, limit in PRODUCTION_LIMITS.items():
            value = getattr(self, name, None)
            try:
                ok = bool(
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and math.isfinite(value)
                    and 0 < value <= limit
                )
            except (OverflowError, TypeError, ValueError):
                ok = False
            if not ok:
                problems.append(f"{name} must be > 0 and <= {limit:g} in production")
        techniques = getattr(self, "techniques", None)
        if not isinstance(techniques, (list, tuple)) or not techniques:
            problems.append("techniques must be a non-empty list")
            techniques = []
        if not all(type(t) is str for t in techniques):
            problems.append("technique names must be plain strings")
        forbidden = {normalize_technique(t) for t in PRODUCTION_FORBIDDEN_TECHNIQUES}
        banned = sorted(
            t for t in techniques if type(t) is str and normalize_technique(t) in forbidden
        )
        if banned:
            problems.append(f"techniques {banned} are staging-only")
        return problems

    @model_validator(mode="after")
    def _environment_rules(self, info: ValidationInfo) -> "CampaignPolicy":
        env = (info.context or {}).get("environment") if info else None
        if env == "production":
            problems = self.production_violations()
            if problems:
                raise ValueError("production policy rejected: " + "; ".join(problems))
        return self


def validate_policy_for_target(policy: CampaignPolicy, target: TargetConfig) -> CampaignPolicy:
    """Re-validate ``policy`` under the target's environment; raises on violation."""
    return CampaignPolicy.model_validate(
        policy.model_dump(), context={"environment": target.environment}
    )


class CampaignRequest(_Contract):
    """A campaign launch: the target plus its policy.

    Campaign creation MUST validate through this model. A bare
    ``CampaignPolicy`` cannot see the target's environment, so on its own it
    would let a production target run with staging limits. This validator
    always applies the section-4 rules, with no context required.
    """

    target: TargetConfig
    policy: CampaignPolicy

    @model_validator(mode="after")
    def _enforce_environment(self) -> "CampaignRequest":
        if self.target.environment == "production":
            problems = self.policy.production_violations()
            if problems:
                raise ValueError("production policy rejected: " + "; ".join(problems))
        return self


# ── Conversation records ─────────────────────────────────────────────────────


class ToolCallObservation(_Contract):
    """One tool call the target made, as observed from its response.

    ``source="structured"`` means it was read from ``tool_trace_path``;
    ``"heuristic"`` means it was guessed from reply text and is weaker evidence.
    """

    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    call_id: str | None = None
    source: Literal["structured", "heuristic"] = "structured"


class Turn(_Contract):
    conversation_id: str
    index: int = Field(ge=0)
    role_sent: Literal["user"] = "user"
    message: str
    response_text: str
    tool_calls: list[ToolCallObservation] = Field(default_factory=list)
    http_status: int | None = Field(default=None, ge=100, le=599)
    latency_ms: float = Field(ge=0)
    monitor_hits: list[str] = Field(default_factory=list)
    error: str | None = None


ConversationStatus = Literal[
    "running",
    "stopped_budget",
    "stopped_monitor",
    "stopped_target_refusal_streak",
    "stopped_target_error_streak",
    "stopped_killed",
    "stopped_planner_guardrail",
    "completed",
    "cancelled",
    "error",
]
TERMINAL_CONVERSATION_STATUSES = frozenset(
    {
        "stopped_budget",
        "stopped_monitor",
        "stopped_target_refusal_streak",
        "stopped_target_error_streak",
        "stopped_killed",
        "stopped_planner_guardrail",
        "completed",
        "cancelled",
        "error",
    }
)


class Conversation(_Contract):
    conversation_id: str
    campaign_id: str
    technique: str
    trial_index: int = Field(ge=0)
    status: ConversationStatus = "running"
    turns: list[Turn] = Field(default_factory=list)
    target_session_ref: str | None = None

    @model_validator(mode="after")
    def _turns_consistent(self) -> "Conversation":
        for expected, turn in enumerate(self.turns):
            if turn.conversation_id != self.conversation_id:
                raise ValueError(f"turn {turn.index} belongs to another conversation")
            if turn.index != expected:
                raise ValueError("turn indices must be contiguous from 0")
        return self


# ── Evaluation ───────────────────────────────────────────────────────────────

Verdict = Literal["confirmed", "unconfirmed", "inconclusive", "failed"]


class JudgeVote(_Contract):
    """One independent judge sample (temperature 0) over a full transcript.

    A vote is a judgement (``unsafe``/``safe``/``inconclusive``); the
    conversation-level ``Verdict`` comes from majority + the deterministic
    consensus table.
    """

    vote_index: int = Field(ge=0)
    judgement: Literal["unsafe", "safe", "inconclusive"]
    first_failing_turn: int | None = Field(default=None, ge=0)
    asi_class: AsiCode | None = None
    severity: Severity = "info"
    confidence: float = Field(ge=0, le=1)
    rationale: str = ""
    model_name: str | None = None
    # Informational only: Backboard has no temperature parameter, so this
    # records the intended setting rather than enforcing it.
    temperature: float = Field(default=0.0, ge=0)


class ConversationVerdict(_Contract):
    conversation_id: str
    verdict: Verdict
    first_failing_turn: int | None = Field(default=None, ge=0)
    deterministic_hits: list[str] = Field(default_factory=list)
    judge_votes: list[JudgeVote] = Field(default_factory=list)
    judge_agreement: float = Field(ge=0, le=1)
    severity: Severity
    asi_class: AsiCode
    rationale: str = ""


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054) -> tuple[float, float]:
    """95% Wilson score interval. ``(0.0, 1.0)`` when there are no trials."""
    if trials <= 0:
        return 0.0, 1.0
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


class TechniqueResult(_Contract):
    """Aggregate over the independent trials of one technique."""

    technique: str
    trials: int = Field(ge=0)
    confirmed: int = Field(ge=0)
    success_rate: float = Field(ge=0, le=1)
    ci95_low: float = Field(ge=0, le=1)
    ci95_high: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def _consistent(self) -> "TechniqueResult":
        if self.confirmed > self.trials:
            raise ValueError("confirmed cannot exceed trials")
        eps = 1e-9
        if not (self.ci95_low - eps <= self.success_rate <= self.ci95_high + eps):
            raise ValueError("success_rate must lie inside [ci95_low, ci95_high]")
        return self

    @classmethod
    def from_counts(cls, technique: str, trials: int, confirmed: int) -> "TechniqueResult":
        low, high = wilson_interval(confirmed, trials)
        rate = confirmed / trials if trials else 0.0
        return cls(
            technique=technique,
            trials=trials,
            confirmed=confirmed,
            success_rate=rate,
            ci95_low=low,
            ci95_high=high,
        )


# ── SSE v2 events ────────────────────────────────────────────────────────────

SSE_EVENT_TYPES = (
    "campaign_started",
    "conversation_started",
    "turn",
    "monitor_hit",
    "conversation_finished",
    "verdict",
    "budget_update",
    "campaign_complete",
    "campaign_failed",
    "campaign_cancelled",
)
SseEventType = Literal[
    "campaign_started",
    "conversation_started",
    "turn",
    "monitor_hit",
    "conversation_finished",
    "verdict",
    "budget_update",
    "campaign_complete",
    "campaign_failed",
    "campaign_cancelled",
]

PREVIEW_MAX_CHARS = 280
TEXT_MAX_CHARS = 500
_ELLIPSIS = "…"


def truncate_preview(text: str | None, limit: int = PREVIEW_MAX_CHARS) -> str | None:
    """Cut ``text`` to at most ``limit`` characters, ending in "…" when cut."""
    if text is None or len(text) <= limit:
        return text
    return text[: limit - len(_ELLIPSIS)] + _ELLIPSIS


class CampaignStartedPayload(_Contract):
    campaign_id: str
    target_id: str
    environment: Environment
    techniques: list[str]
    trials_per_technique: int = Field(ge=1)
    total_conversations: int = Field(ge=0)


class ConversationStartedPayload(_Contract):
    campaign_id: str
    conversation_id: str
    technique: str
    trial_index: int = Field(ge=0)


class TurnPayload(_Contract):
    """Redacted preview of a turn. Full text is only available via the API."""

    campaign_id: str
    conversation_id: str
    index: int = Field(ge=0)
    message_preview: str
    response_preview: str
    tool_call_names: list[str] = Field(default_factory=list)
    http_status: int | None = Field(default=None, ge=100, le=599)
    latency_ms: float = Field(ge=0)
    monitor_hits: list[str] = Field(default_factory=list)
    error: str | None = None

    @field_validator("message_preview", "response_preview")
    @classmethod
    def _cap_preview(cls, v: str) -> str:
        return truncate_preview(v)

    @field_validator("error")
    @classmethod
    def _cap_error(cls, v: str | None) -> str | None:
        return truncate_preview(v, TEXT_MAX_CHARS)


class MonitorHitPayload(_Contract):
    campaign_id: str
    conversation_id: str
    turn_index: int = Field(ge=0)
    hit: str
    severity: Severity
    stops_conversation: bool = False


class ConversationFinishedPayload(_Contract):
    campaign_id: str
    conversation_id: str
    status: ConversationStatus
    turns: int = Field(ge=0)


class VerdictPayload(_Contract):
    campaign_id: str
    verdict: ConversationVerdict

    @field_validator("verdict")
    @classmethod
    def _cap_rationale(cls, v: ConversationVerdict) -> ConversationVerdict:
        # The stored verdict keeps its full rationale; the event carries a capped one.
        capped = truncate_preview(v.rationale, TEXT_MAX_CHARS)
        return v if capped == v.rationale else v.model_copy(update={"rationale": capped})


class BudgetUpdatePayload(_Contract):
    campaign_id: str
    requests_used: int = Field(ge=0)
    max_total_requests: int = Field(ge=1)
    llm_cost_usd: float = Field(ge=0)
    max_llm_cost_usd: float = Field(ge=0)


class CampaignCompletePayload(_Contract):
    campaign_id: str
    conversations: int = Field(ge=0)
    confirmed: int = Field(ge=0)
    technique_results: list[TechniqueResult] = Field(default_factory=list)
    duration_seconds: float = Field(ge=0)


class CampaignFailedPayload(_Contract):
    campaign_id: str
    message: str

    @field_validator("message")
    @classmethod
    def _cap_message(cls, v: str) -> str:
        return truncate_preview(v, TEXT_MAX_CHARS)


class CampaignCancelledPayload(_Contract):
    campaign_id: str
    reason: Literal["user", "kill_switch", "budget"] = "user"
    cancelled_by: str | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class _Event(_Contract):
    timestamp: datetime = Field(default_factory=_utcnow)
    seq: int = Field(ge=0)

    def to_sse(self) -> str:
        """Wire format: ``id`` carries ``seq`` so clients resume via Last-Event-ID."""
        return f"id: {self.seq}\ndata: {self.model_dump_json()}\n\n"


class CampaignStartedEvent(_Event):
    type: Literal["campaign_started"] = "campaign_started"
    payload: CampaignStartedPayload


class ConversationStartedEvent(_Event):
    type: Literal["conversation_started"] = "conversation_started"
    payload: ConversationStartedPayload


class TurnEvent(_Event):
    type: Literal["turn"] = "turn"
    payload: TurnPayload


class MonitorHitEvent(_Event):
    type: Literal["monitor_hit"] = "monitor_hit"
    payload: MonitorHitPayload


class ConversationFinishedEvent(_Event):
    type: Literal["conversation_finished"] = "conversation_finished"
    payload: ConversationFinishedPayload


class VerdictEvent(_Event):
    type: Literal["verdict"] = "verdict"
    payload: VerdictPayload


class BudgetUpdateEvent(_Event):
    type: Literal["budget_update"] = "budget_update"
    payload: BudgetUpdatePayload


class CampaignCompleteEvent(_Event):
    type: Literal["campaign_complete"] = "campaign_complete"
    payload: CampaignCompletePayload


class CampaignFailedEvent(_Event):
    type: Literal["campaign_failed"] = "campaign_failed"
    payload: CampaignFailedPayload


class CampaignCancelledEvent(_Event):
    type: Literal["campaign_cancelled"] = "campaign_cancelled"
    payload: CampaignCancelledPayload


SseEvent = Annotated[
    Union[
        CampaignStartedEvent,
        ConversationStartedEvent,
        TurnEvent,
        MonitorHitEvent,
        ConversationFinishedEvent,
        VerdictEvent,
        BudgetUpdateEvent,
        CampaignCompleteEvent,
        CampaignFailedEvent,
        CampaignCancelledEvent,
    ],
    Field(discriminator="type"),
]
SSE_EVENT_ADAPTER: TypeAdapter[Any] = TypeAdapter(SseEvent)


def parse_sse_event(data: str | bytes | dict[str, Any]) -> Any:
    """Parse one event (JSON text or dict) into its typed model."""
    if isinstance(data, (str, bytes)):
        return SSE_EVENT_ADAPTER.validate_json(data)
    return SSE_EVENT_ADAPTER.validate_python(data)


__all__ = [
    "ASI_CODE_PATTERN",
    "AsiCode",
    "BearerAuth",
    "BudgetUpdateEvent",
    "BudgetUpdatePayload",
    "CampaignCancelledEvent",
    "CampaignCancelledPayload",
    "CampaignCompleteEvent",
    "CampaignCompletePayload",
    "CampaignFailedEvent",
    "CampaignFailedPayload",
    "CampaignPolicy",
    "CampaignRequest",
    "CampaignStartedEvent",
    "CampaignStartedPayload",
    "Conversation",
    "ConversationFinishedEvent",
    "ConversationFinishedPayload",
    "ConversationStartedEvent",
    "ConversationStartedPayload",
    "ConversationStatus",
    "ConversationVerdict",
    "CookieLoginAuth",
    "HeaderAuth",
    "JudgeVote",
    "MonitorHitEvent",
    "MonitorHitPayload",
    "NoAuth",
    "OAuthClientCredentialsAuth",
    "PREVIEW_MAX_CHARS",
    "PRODUCTION_FORBIDDEN_TECHNIQUES",
    "PRODUCTION_LIMITS",
    "RESERVED_HEADERS",
    "SECRET_MASK",
    "SSE_EVENT_ADAPTER",
    "SSE_EVENT_TYPES",
    "SseEvent",
    "SseEventType",
    "TEMPLATE_PLACEHOLDERS",
    "TERMINAL_CONVERSATION_STATUSES",
    "TEXT_MAX_CHARS",
    "TargetAuth",
    "TargetConfig",
    "TechniqueResult",
    "ToolCallObservation",
    "Turn",
    "TurnEvent",
    "TurnPayload",
    "Verdict",
    "VerdictEvent",
    "VerdictPayload",
    "normalize_asi_code",
    "normalize_technique",
    "parse_sse_event",
    "truncate_preview",
    "validate_policy_for_target",
    "validate_request_template",
    "wilson_interval",
]
