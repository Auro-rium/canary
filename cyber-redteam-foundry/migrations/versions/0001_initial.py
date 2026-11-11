"""v2 data layer: initial schema

Revision ID: 0001
Revises:
Create Date: 2026-11-10
"""
import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

EMBEDDING_DIM = 384


def _ts(name: str = "created_at", nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    embedding = sa.JSON().with_variant(Vector(EMBEDDING_DIM), "postgresql")

    op.create_table(
        "targets",
        sa.Column("target_id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("endpoint", sa.Text, nullable=False),
        sa.Column("method", sa.String(8), nullable=False),
        sa.Column("auth_public", sa.JSON, nullable=False),
        sa.Column("request_template", sa.Text),
        sa.Column("response_path", sa.String(500)),
        sa.Column("session_mode", sa.String(32), nullable=False),
        sa.Column("session_id_path", sa.String(500)),
        sa.Column("tool_trace_path", sa.String(500)),
        sa.Column("streaming", sa.String(8), nullable=False),
        sa.Column("timeout_s", sa.Integer, nullable=False),
        sa.Column("verified", sa.Boolean, nullable=False),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("retention_days", sa.Integer),
        _ts(),
    )
    op.create_table(
        "target_secrets",
        sa.Column(
            "target_id", sa.String(36), sa.ForeignKey("targets.target_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("secrets", sa.Text, nullable=False),
        _ts("updated_at"),
    )
    op.create_table(
        "target_verification",
        sa.Column(
            "target_id", sa.String(36), sa.ForeignKey("targets.target_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("token_hash", sa.String(128)),
        sa.Column("method", sa.String(32)),
        _ts("verified_at", nullable=True),
        sa.Column("allowed_auth_hosts", sa.JSON, nullable=False),
        _ts(),
    )
    op.create_table(
        "campaigns",
        sa.Column("campaign_id", sa.String(64), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.target_id"), nullable=False),
        sa.Column("policy", sa.JSON, nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_by", sa.String(200)),
        _ts(),
        _ts("finished_at", nullable=True),
    )
    op.create_index("ix_campaigns_target_id", "campaigns", ["target_id"])
    op.create_table(
        "conversations",
        sa.Column("conversation_id", sa.String(64), primary_key=True),
        sa.Column(
            "campaign_id", sa.String(64), sa.ForeignKey("campaigns.campaign_id"), nullable=False
        ),
        sa.Column("technique", sa.String(100), nullable=False),
        sa.Column("trial_index", sa.Integer, nullable=False),
        sa.Column("status", sa.String(48), nullable=False),
        sa.Column("target_session_ref", sa.Text),
        _ts(),
        sa.UniqueConstraint("campaign_id", "technique", "trial_index", name="uq_conv_trial"),
    )
    op.create_index("ix_conversations_campaign_id", "conversations", ["campaign_id"])
    op.create_table(
        "turns",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "conversation_id", sa.String(64),
            sa.ForeignKey("conversations.conversation_id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("idx", sa.Integer, nullable=False),
        sa.Column("role_sent", sa.String(16), nullable=False),
        sa.Column("message", sa.Text),
        sa.Column("response_text", sa.Text),
        sa.Column("redacted_message_preview", sa.Text, nullable=False),
        sa.Column("redacted_preview", sa.Text, nullable=False),
        sa.Column("redaction_hits", sa.JSON, nullable=False),
        sa.Column("tool_calls", sa.JSON, nullable=False),
        sa.Column("tool_calls_raw", sa.Text),
        sa.Column("http_status", sa.Integer),
        sa.Column("latency_ms", sa.Float, nullable=False),
        sa.Column("monitor_hits", sa.JSON, nullable=False),
        sa.Column("error", sa.Text),
        _ts(),
        _ts("purged_at", nullable=True),
        sa.UniqueConstraint("conversation_id", "idx", name="uq_turn_idx"),
    )
    op.create_index("ix_turns_conversation_id", "turns", ["conversation_id"])
    op.create_index("ix_turns_created_at", "turns", ["created_at"])
    op.create_table(
        "judge_votes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "conversation_id", sa.String(64),
            sa.ForeignKey("conversations.conversation_id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("vote_index", sa.Integer, nullable=False),
        sa.Column("judgement", sa.String(16), nullable=False),
        sa.Column("first_failing_turn", sa.Integer),
        sa.Column("asi_class", sa.String(8)),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.Float, nullable=False),
        sa.Column("rationale", sa.Text, nullable=False),
        sa.Column("model_name", sa.String(200)),
        sa.Column("temperature", sa.Float, nullable=False),
        sa.UniqueConstraint("conversation_id", "vote_index", name="uq_vote_idx"),
    )
    op.create_index("ix_judge_votes_conversation_id", "judge_votes", ["conversation_id"])
    op.create_table(
        "verdicts",
        sa.Column(
            "conversation_id", sa.String(64),
            sa.ForeignKey("conversations.conversation_id", ondelete="CASCADE"), primary_key=True,
        ),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("first_failing_turn", sa.Integer),
        sa.Column("deterministic_hits", sa.JSON, nullable=False),
        sa.Column("judge_agreement", sa.Float, nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("asi_class", sa.String(8), nullable=False),
        sa.Column("rationale", sa.Text, nullable=False),
        _ts(),
    )
    op.create_table(
        "technique_results",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "campaign_id", sa.String(64),
            sa.ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("technique", sa.String(100), nullable=False),
        sa.Column("trials", sa.Integer, nullable=False),
        sa.Column("confirmed", sa.Integer, nullable=False),
        sa.Column("success_rate", sa.Float, nullable=False),
        sa.Column("ci95_low", sa.Float, nullable=False),
        sa.Column("ci95_high", sa.Float, nullable=False),
        sa.UniqueConstraint("campaign_id", "technique", name="uq_tr_campaign_tech"),
    )
    op.create_index("ix_technique_results_campaign_id", "technique_results", ["campaign_id"])
    op.create_table(
        "findings",
        sa.Column("finding_id", sa.String(64), primary_key=True),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.target_id"), nullable=False),
        sa.Column("component", sa.String(200), nullable=False),
        sa.Column("technique", sa.String(100), nullable=False),
        sa.Column("asi_class", sa.String(8), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("first_seen_campaign", sa.String(64), sa.ForeignKey("campaigns.campaign_id")),
        sa.Column("last_seen_campaign", sa.String(64), sa.ForeignKey("campaigns.campaign_id")),
        sa.Column("seen_in_campaigns", sa.JSON, nullable=False),
        sa.Column(
            "conversation_id", sa.String(64),
            sa.ForeignKey("conversations.conversation_id", ondelete="SET NULL"),
        ),
        sa.Column("embedding", embedding),
        _ts(),
        _ts("updated_at"),
        sa.CheckConstraint(
            "status IN ('open','wont_fix','false_positive','inconclusive','needs_review')",
            name="ck_findings_status",
        ),
    )
    op.create_index("ix_findings_target_status", "findings", ["target_id", "status"])
    op.create_index("ix_findings_conversation_id", "findings", ["conversation_id"])
    op.create_index("ix_findings_first_seen_campaign", "findings", ["first_seen_campaign"])
    op.create_index("ix_findings_last_seen_campaign", "findings", ["last_seen_campaign"])
    if bind.dialect.name == "postgresql":
        op.create_index(
            "ix_findings_embedding_hnsw", "findings", ["embedding"],
            postgresql_using="hnsw", postgresql_ops={"embedding": "vector_cosine_ops"},
        )
    op.create_table(
        "finding_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "finding_id", sa.String(64),
            sa.ForeignKey("findings.finding_id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("from_status", sa.String(16)),
        sa.Column("to_status", sa.String(16), nullable=False),
        sa.Column("reviewer_id", sa.String(200)),
        sa.Column("rationale", sa.Text),
        _ts("at"),
    )
    op.create_index("ix_finding_events_finding_id", "finding_events", ["finding_id"])
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("object", sa.String(300), nullable=False),
        _ts("at"),
        sa.Column("details", sa.JSON, nullable=False),
    )
    op.create_index("ix_audit_log_at", "audit_log", ["at"])
    op.create_index("ix_audit_log_object", "audit_log", ["object"])
    op.create_table(
        "budget_ledger",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "campaign_id", sa.String(64), sa.ForeignKey("campaigns.campaign_id"), nullable=False
        ),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("amount", sa.Float, nullable=False),
        _ts("at"),
        sa.CheckConstraint("kind IN ('requests','tokens','usd')", name="ck_budget_kind"),
    )
    op.create_index("ix_budget_ledger_campaign_kind", "budget_ledger", ["campaign_id", "kind"])


def downgrade() -> None:
    for table in (
        "budget_ledger",
        "audit_log",
        "finding_events",
        "findings",
        "technique_results",
        "verdicts",
        "judge_votes",
        "turns",
        "conversations",
        "campaigns",
        "target_verification",
        "target_secrets",
        "targets",
    ):
        op.drop_table(table)
