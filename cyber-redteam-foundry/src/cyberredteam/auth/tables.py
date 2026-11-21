"""Auth tables (WP8): orgs, users, API keys, browser sessions, OIDC login state.

Registered on the shared v2 ORM ``Base`` (revision ``0003``). Credentials are
never stored: API keys and session tokens are kept as SHA-256 hashes only, and
the OIDC ``state`` is stored hashed too.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from cyberredteam.storage.v2.orm import Base, utcnow

ROLES = ("viewer", "operator", "admin")


class OrgRow(Base):
    __tablename__ = "orgs"

    org_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserRow(Base):
    """One user belongs to exactly one org with one role.

    A row with ``oidc_subject`` NULL is an invitation: the first OIDC login whose
    *verified* email matches (and whose provider matches, if set) binds to it.
    """

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("oidc_provider", "oidc_subject", name="uq_users_oidc_identity"),
        Index("ix_users_org_id", "org_id"),
        Index("ix_users_email", "email"),
        CheckConstraint("role IN ('viewer','operator','admin')", name="ck_users_role"),
    )

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(36), ForeignKey("orgs.org_id"))
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    role: Mapped[str] = mapped_column(String(16))
    # Extra grants on top of the role (only "evidence:read_raw" is grantable).
    extra_permissions: Mapped[list] = mapped_column(JSON, default=list)
    oidc_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    oidc_subject: Mapped[str | None] = mapped_column(String(200), nullable=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApiKeyRow(Base):
    """CI API key. ``key_id`` is the public lookup prefix; only the hash of the full key is stored."""

    __tablename__ = "api_keys"
    __table_args__ = (Index("ix_api_keys_user_id", "user_id"),)

    key_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(String(200), default="")
    key_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthSessionRow(Base):
    """Browser session created by an OIDC login. Only token hashes are stored."""

    __tablename__ = "auth_sessions"
    __table_args__ = (Index("ix_auth_sessions_user_id", "user_id"),)

    session_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE")
    )
    csrf_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OidcLoginStateRow(Base):
    """Pending OIDC authorization request (one-time, short-lived)."""

    __tablename__ = "oidc_login_states"

    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32))
    code_verifier: Mapped[str] = mapped_column(String(128))
    redirect_to: Mapped[str] = mapped_column(String(500), default="/")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
