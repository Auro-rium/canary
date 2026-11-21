"""Request and response models for /api/v2 (WP8). The OpenAPI schema is built from these.

Secrets never appear in a response model: target auth is returned as its masked
JSON form (``SecretStr`` fields are ``"**********"``) and the on-call webhook
only as a boolean.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from cyberredteam.contracts import (
    CampaignPolicy,
    Conversation,
    ConversationVerdict,
    TargetAuth,
    TechniqueResult,
)

VerifyMethod = Literal["http_wellknown", "dns_txt", "response_header"]
CampaignStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
FindingStatus = Literal["open", "wont_fix", "false_positive", "inconclusive", "needs_review"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ── Auth ─────────────────────────────────────────────────────────────────────


class Me(BaseModel):
    user_id: str
    org_id: str
    email: str | None
    display_name: str
    role: Literal["viewer", "operator", "admin"]
    permissions: list[str]
    auth_method: Literal["session", "api_key"]
    # Informational only (CANARY_PLATFORM_ADMINS); the server enforces it on every call.
    is_platform_admin: bool = False
    # Session logins only: send it back as X-CSRF-Token on POST/PUT/PATCH/DELETE.
    csrf_token: str | None = None


class ProvidersView(BaseModel):
    providers: list[str]


class ApiKeyCreate(_Strict):
    name: str = Field(default="", max_length=200)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class ApiKeyView(BaseModel):
    key_id: str
    name: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiKeyCreated(BaseModel):
    key: ApiKeyView
    # Shown once; only its hash is stored.
    api_key: str


class ApiKeyList(BaseModel):
    items: list[ApiKeyView]


# ── Targets ──────────────────────────────────────────────────────────────────


class TargetCreate(_Strict):
    """``TargetConfig`` without the server-assigned ``target_id`` and ``verified``."""

    name: str
    endpoint: HttpUrl
    method: Literal["POST"] = "POST"
    auth: TargetAuth
    request_template: str | None = None
    response_path: str | None = None
    session_mode: Literal["stateless_history", "server_session", "cookie"]
    session_id_path: str | None = None
    tool_trace_path: str | None = None
    streaming: Literal["none", "sse", "ndjson"] = "none"
    timeout_s: int = 60
    environment: Literal["staging", "production"]
    allowed_auth_hosts: list[str] = Field(default_factory=list)
    # Per-target on-call webhook for critical monitor hits (public https/http,
    # SSRF-checked). Stored encrypted and never returned.
    oncall_webhook_url: HttpUrl | None = None
    # Accepted for client convenience and ignored: both are server-assigned.
    target_id: str | None = Field(default=None, description="Ignored (server-assigned).")
    verified: bool | None = Field(default=None, description="Ignored (set only by verification).")


class TargetUpdate(_Strict):
    """Partial update. ``environment`` cannot change (create a new target instead).

    ``auth``: give the full object; secret fields left out keep their stored
    value when the auth ``type`` is unchanged. Changing the endpoint, the auth
    type or URLs, or ``allowed_auth_hosts`` clears verification.
    ``oncall_webhook_url: null`` removes the webhook.
    """

    name: str | None = None
    endpoint: HttpUrl | None = None
    auth: dict[str, Any] | None = None
    request_template: str | None = None
    response_path: str | None = None
    session_mode: Literal["stateless_history", "server_session", "cookie"] | None = None
    session_id_path: str | None = None
    tool_trace_path: str | None = None
    streaming: Literal["none", "sse", "ndjson"] | None = None
    timeout_s: int | None = None
    environment: Literal["staging", "production"] | None = None
    allowed_auth_hosts: list[str] | None = None
    oncall_webhook_url: HttpUrl | None = None


class TargetView(BaseModel):
    target_id: str
    name: str
    endpoint: str
    method: str
    # Masked: every secret field is "**********".
    auth: dict[str, Any]
    request_template: str | None
    response_path: str | None
    session_mode: str
    session_id_path: str | None
    tool_trace_path: str | None
    streaming: str
    timeout_s: int
    verified: bool
    environment: Literal["staging", "production"]
    allowed_auth_hosts: list[str]
    verified_method: str | None
    verified_at: datetime | None
    oncall_webhook_configured: bool
    created_at: datetime | None


class TargetList(BaseModel):
    items: list[TargetView]


class VerificationInstructions(BaseModel):
    http_wellknown: dict[str, str]
    dns_txt: dict[str, str]
    response_header: dict[str, str]


class TargetCreated(BaseModel):
    target: TargetView
    # Shown once; only its hash is stored.
    verification_token: str
    verification: VerificationInstructions


class VerifyRequest(_Strict):
    method: VerifyMethod


class VerifyResult(BaseModel):
    target: TargetView
    verified: bool
    method: VerifyMethod
    reason: str


class TestConnectionResult(BaseModel):
    """Outcome of the one fixed benign probe. Never carries credentials."""

    __test__ = False  # not a pytest class

    # True when the target answered 2xx and the reply was parsed to text.
    parse_ok: bool
    http_status: int | None = None
    latency_ms: float
    # The parsed reply, redacted and truncated. Empty when parsing failed.
    reply: str = ""
    # Failure kind only (e.g. "timeout", "http_4xx", "extract_failed"); no detail text.
    error: str | None = None


class TargetUpdated(BaseModel):
    target: TargetView
    verification_reset: bool


# ── Campaigns ────────────────────────────────────────────────────────────────


class CampaignCreate(_Strict):
    target_id: str
    policy: CampaignPolicy


class CampaignSummary(BaseModel):
    campaign_id: str
    target_id: str
    target_name: str
    environment: Literal["staging", "production"]
    status: CampaignStatus
    created_by: str | None
    created_at: datetime | None
    finished_at: datetime | None
    total_conversations: int
    confirmed: int


class CampaignPage(BaseModel):
    items: list[CampaignSummary]
    total: int
    page: int
    page_size: int


class ConversationSummary(BaseModel):
    conversation_id: str
    technique: str
    trial_index: int
    status: str
    turns: int
    verdict: str | None


class BudgetState(BaseModel):
    requests_used: float
    max_total_requests: int
    llm_cost_usd: float
    max_llm_cost_usd: float


class CampaignDetail(CampaignSummary):
    policy: CampaignPolicy
    conversations: list[ConversationSummary]
    technique_results: list[TechniqueResult]
    budget: BudgetState
    # Highest persisted SSE seq; resume the event stream after it.
    last_seq: int


class CancelResult(BaseModel):
    campaign_id: str
    status: Literal["cancelling", "cancelled"]


class KillSwitchBody(_Strict):
    enabled: bool
    reason: str | None = Field(default=None, max_length=500)


class KillSwitchState(BaseModel):
    enabled: bool
    active: bool  # same as enabled (UI alias)
    env: bool
    db: bool
    updated_by: str | None
    updated_at: str | None


# ── Evidence, findings ───────────────────────────────────────────────────────


class ConversationDetail(BaseModel):
    conversation: Conversation
    verdict: ConversationVerdict | None
    # True only when ?raw=true was requested and allowed (that read is audited).
    raw: bool


class FindingView(BaseModel):
    finding_id: str
    target_id: str
    campaign_id: str | None
    conversation_id: str | None
    technique: str
    asi_class: str
    severity: str
    status: FindingStatus
    title: str
    seen_in_campaigns: list[str]
    first_failing_turn: int | None
    # Redacted verdict rationale ("" when no verdict exists).
    rationale: str
    reviewer_id: str | None
    created_at: datetime | None
    updated_at: datetime | None


class FindingPage(BaseModel):
    items: list[FindingView]
    total: int
    page: int
    page_size: int


class FindingEventView(BaseModel):
    from_status: FindingStatus | None
    to_status: FindingStatus
    reviewer_id: str | None
    rationale: str | None
    at: datetime


class FindingDetail(FindingView):
    events: list[FindingEventView]


class FindingTransition(_Strict):
    status: FindingStatus
    rationale: str | None = Field(default=None, max_length=4000)
