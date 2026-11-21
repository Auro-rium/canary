"""Persistence for orgs, users, API keys, sessions and OIDC login state (WP8)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.auth import tokens
from cyberredteam.auth.principal import GRANTABLE_PERMISSIONS, Principal, permissions_for
from cyberredteam.auth.tables import (
    ROLES,
    ApiKeyRow,
    AuthSessionRow,
    OidcLoginStateRow,
    OrgRow,
    UserRow,
)
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.repositories import _audit_row


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class AuthError(Exception):
    """Login refused. The message is a fixed string, safe to show."""


@dataclass(frozen=True)
class UserInfo:
    user_id: str
    org_id: str
    email: str | None
    display_name: str
    role: str
    extra_permissions: tuple[str, ...]
    disabled: bool


@dataclass(frozen=True)
class ApiKeyInfo:
    key_id: str
    name: str
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True)
class LoginState:
    provider: str
    code_verifier: str
    redirect_to: str


def _user(row: UserRow) -> UserInfo:
    return UserInfo(
        user_id=row.user_id, org_id=row.org_id, email=row.email,
        display_name=row.display_name or "", role=row.role,
        extra_permissions=tuple(row.extra_permissions or ()), disabled=bool(row.disabled),
    )


def _principal(row: UserRow, method: str, **kw) -> Principal:
    return Principal(
        user_id=row.user_id, org_id=row.org_id, role=row.role, auth_method=method,
        email=row.email, display_name=row.display_name or "",
        permissions=permissions_for(row.role, tuple(row.extra_permissions or ())), **kw,
    )


class AuthRepo:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    @property
    def factory(self) -> sessionmaker[Session]:
        return self._factory

    # ── Orgs and users ──────────────────────────────────────────────────────

    def create_org(self, name: str) -> str:
        org_id = str(uuid.uuid4())
        try:
            with session_scope(self._factory) as s:
                s.add(OrgRow(org_id=org_id, name=name.strip()))
        except IntegrityError:
            raise ValueError(f"org {name!r} already exists") from None
        return org_id

    def org_by_name(self, name: str) -> str | None:
        with session_scope(self._factory) as s:
            return s.scalar(select(OrgRow.org_id).where(OrgRow.name == name.strip()))

    def create_user(
        self,
        org_id: str,
        role: str,
        *,
        email: str | None = None,
        display_name: str = "",
        oidc_provider: str | None = None,
        oidc_subject: str | None = None,
        extra_permissions: list[str] | None = None,
    ) -> str:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        extra = list(extra_permissions or [])
        if set(extra) - GRANTABLE_PERMISSIONS:
            raise ValueError("only evidence:read_raw may be granted on top of a role")
        user_id = str(uuid.uuid4())
        with session_scope(self._factory) as s:
            if s.get(OrgRow, org_id) is None:
                raise KeyError(org_id)
            s.add(
                UserRow(
                    user_id=user_id, org_id=org_id, role=role,
                    email=email.strip().lower() if email else None,
                    display_name=display_name, oidc_provider=oidc_provider,
                    oidc_subject=oidc_subject, extra_permissions=extra,
                )
            )
        return user_id

    def get_user(self, user_id: str) -> UserInfo | None:
        with session_scope(self._factory) as s:
            row = s.get(UserRow, user_id)
            return _user(row) if row else None

    def set_role(self, user_id: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        with session_scope(self._factory) as s:
            row = s.get(UserRow, user_id)
            if row is None:
                raise KeyError(user_id)
            row.role = role

    def set_disabled(self, user_id: str, disabled: bool) -> None:
        with session_scope(self._factory) as s:
            row = s.get(UserRow, user_id)
            if row is None:
                raise KeyError(user_id)
            row.disabled = disabled
            if disabled:  # end every live session at once
                for sess in s.scalars(
                    select(AuthSessionRow).where(AuthSessionRow.user_id == user_id)
                ):
                    sess.revoked_at = sess.revoked_at or _now()

    def resolve_oidc_user(
        self, provider: str, subject: str, email: str | None, email_verified: bool
    ) -> str:
        """The user id for an OIDC identity; binds an invitation on first login.

        Identity is the provider's stable subject, never the email. An email is
        used only once, to bind a pending invitation, and only if verified.
        Unknown identities are refused: membership is never auto-granted.
        """
        with session_scope(self._factory) as s:
            row = s.scalar(
                select(UserRow).where(
                    UserRow.oidc_provider == provider, UserRow.oidc_subject == subject
                )
            )
            if row is None and email and email_verified:
                invites = s.scalars(
                    select(UserRow).where(
                        func.lower(UserRow.email) == email.strip().lower(),
                        UserRow.oidc_subject.is_(None),
                    )
                ).all()
                invites = [r for r in invites if r.oidc_provider in (None, provider)]
                if len(invites) == 1:
                    row = invites[0]
                    row.oidc_provider = provider
                    row.oidc_subject = subject
                    s.add(_audit_row(f"user:{row.user_id}", "user.oidc_bound", f"user:{row.user_id}",
                                     {"provider": provider}))
            if row is None:
                raise AuthError("This account has not been invited to Canary.")
            if row.disabled:
                raise AuthError("This account is disabled.")
            return row.user_id

    # ── API keys ────────────────────────────────────────────────────────────

    def create_api_key(
        self, user_id: str, name: str = "", expires_in_days: int | None = None
    ) -> tuple[str, str]:
        """Return ``(key_id, full_key)``; the full key is not stored and cannot be recovered."""
        key_id, full, key_hash = tokens.new_api_key()
        expires = _now() + timedelta(days=expires_in_days) if expires_in_days else None
        with session_scope(self._factory) as s:
            if s.get(UserRow, user_id) is None:
                raise KeyError(user_id)
            s.add(ApiKeyRow(key_id=key_id, user_id=user_id, name=name, key_hash=key_hash,
                            expires_at=expires))
        return key_id, full

    def list_api_keys(self, user_id: str) -> list[ApiKeyInfo]:
        with session_scope(self._factory) as s:
            rows = s.scalars(
                select(ApiKeyRow).where(ApiKeyRow.user_id == user_id).order_by(ApiKeyRow.created_at)
            ).all()
            return [
                ApiKeyInfo(r.key_id, r.name, _aware(r.created_at), _aware(r.expires_at),
                           _aware(r.last_used_at), _aware(r.revoked_at))
                for r in rows
            ]

    def revoke_api_key(self, user_id: str, key_id: str) -> bool:
        with session_scope(self._factory) as s:
            row = s.get(ApiKeyRow, key_id)
            if row is None or row.user_id != user_id:
                return False
            row.revoked_at = row.revoked_at or _now()
            return True

    def authenticate_api_key(self, presented: str) -> Principal | None:
        key_id = tokens.parse_api_key(presented)
        with session_scope(self._factory) as s:
            row = s.get(ApiKeyRow, key_id) if key_id else None
            if not tokens.key_matches(presented, row.key_hash if row else None):
                return None
            now = _now()
            if row.revoked_at is not None or (row.expires_at and _aware(row.expires_at) <= now):
                return None
            user = s.get(UserRow, row.user_id)
            if user is None or user.disabled:
                return None
            row.last_used_at = now
            return _principal(user, "api_key", api_key_id=row.key_id)

    # ── Sessions ────────────────────────────────────────────────────────────

    def create_session(self, user_id: str, ttl_s: int) -> tuple[str, str]:
        """Return ``(session_token, csrf_token)``; only their hashes are stored."""
        token, token_hash = tokens.new_token()
        csrf, csrf_hash = tokens.new_token()
        with session_scope(self._factory) as s:
            s.add(AuthSessionRow(session_hash=token_hash, user_id=user_id, csrf_hash=csrf_hash,
                                 expires_at=_now() + timedelta(seconds=ttl_s)))
        return token, csrf

    def authenticate_session(self, token: str) -> Principal | None:
        if not token:
            return None
        token_hash = tokens.sha256_hex(token)
        with session_scope(self._factory) as s:
            row = s.get(AuthSessionRow, token_hash)
            if row is None or row.revoked_at is not None or _aware(row.expires_at) <= _now():
                return None
            user = s.get(UserRow, row.user_id)
            if user is None or user.disabled:
                return None
            return _principal(user, "session", session_hash=token_hash, csrf_hash=row.csrf_hash)

    def revoke_session(self, session_hash: str) -> None:
        with session_scope(self._factory) as s:
            row = s.get(AuthSessionRow, session_hash)
            if row is not None:
                row.revoked_at = row.revoked_at or _now()

    # ── OIDC login state ────────────────────────────────────────────────────

    def save_login_state(
        self, state: str, provider: str, code_verifier: str, redirect_to: str, ttl_s: int = 600
    ) -> None:
        with session_scope(self._factory) as s:
            # Opportunistic cleanup of expired rows.
            for old in s.scalars(
                select(OidcLoginStateRow).where(OidcLoginStateRow.expires_at < _now())
            ):
                s.delete(old)
            s.add(OidcLoginStateRow(state_hash=tokens.sha256_hex(state), provider=provider,
                                    code_verifier=code_verifier, redirect_to=redirect_to,
                                    expires_at=_now() + timedelta(seconds=ttl_s)))

    def consume_login_state(self, state: str) -> LoginState | None:
        """One-time: the row is deleted whether or not it is still valid."""
        if not state:
            return None
        with session_scope(self._factory) as s:
            row = s.get(OidcLoginStateRow, tokens.sha256_hex(state), with_for_update=True)
            if row is None:
                return None
            s.delete(row)
            if _aware(row.expires_at) <= _now():
                return None
            return LoginState(row.provider, row.code_verifier, row.redirect_to)
