"""WP8 auth: orgs, users, api_keys, auth_sessions, oidc_login_states; targets.org_id,
targets.archived_at, targets.oncall_webhook (encrypted)

Existing targets get org_id NULL, which makes them visible to no org (fail closed);
assign them with ``cyber-rt auth assign-target``.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-20
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def _ts(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "orgs",
        sa.Column("org_id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        _ts("created_at"),
    )
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("orgs.org_id"), nullable=False),
        sa.Column("email", sa.String(320)),
        sa.Column("display_name", sa.String(200), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("extra_permissions", sa.JSON, nullable=False),
        sa.Column("oidc_provider", sa.String(32)),
        sa.Column("oidc_subject", sa.String(200)),
        sa.Column("disabled", sa.Boolean, nullable=False),
        _ts("created_at"),
        sa.UniqueConstraint("oidc_provider", "oidc_subject", name="uq_users_oidc_identity"),
        sa.CheckConstraint("role IN ('viewer','operator','admin')", name="ck_users_role"),
    )
    op.create_index("ix_users_org_id", "users", ["org_id"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_table(
        "api_keys",
        sa.Column("key_id", sa.String(32), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        _ts("created_at"),
        _ts("expires_at", nullable=True),
        _ts("last_used_at", nullable=True),
        _ts("revoked_at", nullable=True),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_table(
        "auth_sessions",
        sa.Column("session_hash", sa.String(64), primary_key=True),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("csrf_hash", sa.String(64), nullable=False),
        _ts("created_at"),
        _ts("expires_at"),
        _ts("revoked_at", nullable=True),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_table(
        "oidc_login_states",
        sa.Column("state_hash", sa.String(64), primary_key=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("code_verifier", sa.String(128), nullable=False),
        sa.Column("redirect_to", sa.String(500), nullable=False),
        _ts("expires_at"),
    )
    with op.batch_alter_table("targets") as batch:
        batch.add_column(sa.Column("org_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("oncall_webhook", sa.Text, nullable=True))
        batch.create_foreign_key("fk_targets_org_id", "orgs", ["org_id"], ["org_id"])
        batch.create_index("ix_targets_org_id", ["org_id"])


def downgrade() -> None:
    with op.batch_alter_table("targets") as batch:
        batch.drop_index("ix_targets_org_id")
        batch.drop_constraint("fk_targets_org_id", type_="foreignkey")
        batch.drop_column("oncall_webhook")
        batch.drop_column("archived_at")
        batch.drop_column("org_id")
    op.drop_table("oidc_login_states")
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("ix_api_keys_user_id", table_name="api_keys")
    op.drop_table("api_keys")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_org_id", table_name="users")
    op.drop_table("users")
    op.drop_table("orgs")
