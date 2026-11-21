"""WP7 control plane: run_control flags, worker heartbeats, persisted SSE event log

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-11
"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "run_control",
        sa.Column("key", sa.String(128), primary_key=True),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("updated_by", sa.String(200)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "campaign_heartbeats",
        sa.Column(
            "campaign_id", sa.String(64),
            sa.ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), primary_key=True,
        ),
        sa.Column("worker_id", sa.String(100)),
        sa.Column("beat_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "campaign_events",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "campaign_id", sa.String(64),
            sa.ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("campaign_id", "seq", name="uq_campaign_event_seq"),
    )


def downgrade() -> None:
    op.drop_table("campaign_events")
    op.drop_table("campaign_heartbeats")
    op.drop_table("run_control")
