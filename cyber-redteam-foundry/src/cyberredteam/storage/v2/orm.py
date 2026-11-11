"""SQLAlchemy 2.0 ORM for the v2 data layer (WP6).

Columns mirror the models in ``contracts.py``. Evidence (turn message and
response, judge rationale, target secrets) is stored as Fernet ciphertext via
``EncryptedText``; everything shown in UIs or logs comes from the plaintext
``redacted_*`` previews instead.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from cyberredteam.storage.v2.encrypted import EncryptedText

EMBEDDING_DIM = 384  # all-MiniLM-L6-v2, same as the legacy findings table

# pgvector on Postgres, plain JSON list on SQLite.
EmbeddingType = JSON().with_variant(Vector(EMBEDDING_DIM), "postgresql")

BUDGET_KINDS = ("requests", "tokens", "usd")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


def _ts(**kw: Any) -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow, **kw)


class TargetRow(Base):
    __tablename__ = "targets"

    target_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    endpoint: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(8), default="POST")
    # Auth config with every secret field removed; secrets live in target_secrets.
    auth_public: Mapped[dict] = mapped_column(JSON)
    request_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    session_mode: Mapped[str] = mapped_column(String(32))
    session_id_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    tool_trace_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    streaming: Mapped[str] = mapped_column(String(8), default="none")
    timeout_s: Mapped[int] = mapped_column(Integer, default=60)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    environment: Mapped[str] = mapped_column(String(16))
    retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = _ts()


class TargetSecretRow(Base):
    __tablename__ = "target_secrets"

    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.target_id", ondelete="CASCADE"), primary_key=True
    )
    secrets: Mapped[str] = mapped_column(EncryptedText)  # JSON object, encrypted
    updated_at: Mapped[datetime] = _ts()


class TargetVerificationRow(Base):
    __tablename__ = "target_verification"

    target_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("targets.target_id", ondelete="CASCADE"), primary_key=True
    )
    token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    method: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    allowed_auth_hosts: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = _ts()


class CampaignRow(Base):
    __tablename__ = "campaigns"
    __table_args__ = (Index("ix_campaigns_target_id", "target_id"),)

    campaign_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.target_id"))
    policy: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(32), default="queued")
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = _ts()
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ConversationRow(Base):
    __tablename__ = "conversations"
    __table_args__ = (
        UniqueConstraint("campaign_id", "technique", "trial_index", name="uq_conv_trial"),
        Index("ix_conversations_campaign_id", "campaign_id"),
    )

    conversation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(64), ForeignKey("campaigns.campaign_id"))
    technique: Mapped[str] = mapped_column(String(100))
    trial_index: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(48), default="running")
    target_session_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = _ts()


class TurnRow(Base):
    __tablename__ = "turns"
    __table_args__ = (
        UniqueConstraint("conversation_id", "idx", name="uq_turn_idx"),
        Index("ix_turns_conversation_id", "conversation_id"),
        Index("ix_turns_created_at", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("conversations.conversation_id", ondelete="CASCADE")
    )
    idx: Mapped[int] = mapped_column(Integer)
    role_sent: Mapped[str] = mapped_column(String(16), default="user")
    # Encrypted evidence; NULL after the retention purge.
    message: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    response_text: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    redacted_message_preview: Mapped[str] = mapped_column(Text, default="")
    redacted_preview: Mapped[str] = mapped_column(Text, default="")  # response preview
    redaction_hits: Mapped[list] = mapped_column(JSON, default=list)
    tool_calls: Mapped[list] = mapped_column(JSON, default=list)  # redacted copy
    # Raw tool calls as encrypted JSON; NULL after the retention purge.
    tool_calls_raw: Mapped[str | None] = mapped_column(EncryptedText, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    monitor_hits: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)  # redacted
    created_at: Mapped[datetime] = _ts()
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class JudgeVoteRow(Base):
    __tablename__ = "judge_votes"
    __table_args__ = (
        UniqueConstraint("conversation_id", "vote_index", name="uq_vote_idx"),
        Index("ix_judge_votes_conversation_id", "conversation_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    conversation_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("conversations.conversation_id", ondelete="CASCADE")
    )
    vote_index: Mapped[int] = mapped_column(Integer)
    judgement: Mapped[str] = mapped_column(String(16))
    first_failing_turn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    asi_class: Mapped[str | None] = mapped_column(String(8), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    confidence: Mapped[float] = mapped_column(Float)
    rationale: Mapped[str] = mapped_column(EncryptedText, default="")
    model_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    temperature: Mapped[float] = mapped_column(Float, default=0.0)


class VerdictRow(Base):
    __tablename__ = "verdicts"

    conversation_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("conversations.conversation_id", ondelete="CASCADE"),
        primary_key=True,
    )
    verdict: Mapped[str] = mapped_column(String(16))
    first_failing_turn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    deterministic_hits: Mapped[list] = mapped_column(JSON, default=list)
    judge_agreement: Mapped[float] = mapped_column(Float)
    severity: Mapped[str] = mapped_column(String(16))
    asi_class: Mapped[str] = mapped_column(String(8))
    rationale: Mapped[str] = mapped_column(EncryptedText, default="")
    created_at: Mapped[datetime] = _ts()


class TechniqueResultRow(Base):
    __tablename__ = "technique_results"
    __table_args__ = (UniqueConstraint("campaign_id", "technique", name="uq_tr_campaign_tech"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), index=True
    )
    technique: Mapped[str] = mapped_column(String(100))
    trials: Mapped[int] = mapped_column(Integer)
    confirmed: Mapped[int] = mapped_column(Integer)
    success_rate: Mapped[float] = mapped_column(Float)
    ci95_low: Mapped[float] = mapped_column(Float)
    ci95_high: Mapped[float] = mapped_column(Float)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_target_status", "target_id", "status"),
        Index("ix_findings_conversation_id", "conversation_id"),
        Index("ix_findings_first_seen_campaign", "first_seen_campaign"),
        Index("ix_findings_last_seen_campaign", "last_seen_campaign"),
        # pgvector HNSW (Postgres only; the kwargs are ignored on SQLite, where the
        # migration does not create it).
        Index(
            "ix_findings_embedding_hnsw", "embedding",
            postgresql_using="hnsw", postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        CheckConstraint(
            "status IN ('open','wont_fix','false_positive','inconclusive','needs_review')",
            name="ck_findings_status",
        ),
    )

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.target_id"))
    component: Mapped[str] = mapped_column(String(200), default="")
    technique: Mapped[str] = mapped_column(String(100), default="")
    asi_class: Mapped[str] = mapped_column(String(8))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open")
    title: Mapped[str] = mapped_column(Text, default="")
    first_seen_campaign: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("campaigns.campaign_id"), nullable=True
    )
    last_seen_campaign: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("campaigns.campaign_id"), nullable=True
    )
    seen_in_campaigns: Mapped[list] = mapped_column(JSON, default=list)
    conversation_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("conversations.conversation_id", ondelete="SET NULL"), nullable=True
    )
    embedding: Mapped[list | None] = mapped_column(EmbeddingType, nullable=True)
    created_at: Mapped[datetime] = _ts()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class FindingEventRow(Base):
    __tablename__ = "finding_events"
    __table_args__ = (Index("ix_finding_events_finding_id", "finding_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("findings.finding_id", ondelete="CASCADE")
    )
    from_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_status: Mapped[str] = mapped_column(String(16))
    reviewer_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    at: Mapped[datetime] = _ts()


class AuditLogRow(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_log_at", "at"), Index("ix_audit_log_object", "object"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100))
    object: Mapped[str] = mapped_column(String(300))
    at: Mapped[datetime] = _ts()
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class BudgetLedgerRow(Base):
    __tablename__ = "budget_ledger"
    __table_args__ = (
        CheckConstraint("kind IN ('requests','tokens','usd')", name="ck_budget_kind"),
        Index("ix_budget_ledger_campaign_kind", "campaign_id", "kind"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(String(64), ForeignKey("campaigns.campaign_id"))
    kind: Mapped[str] = mapped_column(String(16))
    amount: Mapped[float] = mapped_column(Float)
    at: Mapped[datetime] = _ts()
