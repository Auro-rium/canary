"""Opaque token helpers with hash-only persistence and constant-time checks."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

PROJECT_TOKEN_PREFIX = "canary_project_"


@dataclass(frozen=True, slots=True)
class IssuedProjectToken:
    """The raw token is for one-time delivery; persist only prefix and digest."""

    token: str
    lookup_prefix: str
    token_hash: str


def issue_verification_token() -> str:
    """Generate an ownership challenge token suitable for one-time display."""

    return secrets.token_urlsafe(32)


def hash_verification_token(token: str, *, pepper: str = "") -> str:
    """Return a keyed digest; callers persist this value rather than ``token``."""

    return _token_digest(token, pepper=pepper)


def verify_verification_token(token: str, expected_hash: str, *, pepper: str = "") -> bool:
    """Constant-time verification for a target ownership challenge."""

    return hmac.compare_digest(_token_digest(token, pepper=pepper), expected_hash)


def issue_project_token(*, pepper: str = "") -> IssuedProjectToken:
    """Create a scoped-token envelope; store only ``lookup_prefix`` and hash."""

    lookup_prefix = secrets.token_hex(6)
    secret = secrets.token_urlsafe(32)
    token = f"{PROJECT_TOKEN_PREFIX}{lookup_prefix}.{secret}"
    return IssuedProjectToken(
        token=token,
        lookup_prefix=lookup_prefix,
        token_hash=hash_project_token(token, pepper=pepper),
    )


def parse_project_token(token: str) -> tuple[str, str] | None:
    """Parse a token without validating it; malformed inputs return ``None``."""

    if not isinstance(token, str) or not token.startswith(PROJECT_TOKEN_PREFIX):
        return None
    body = token[len(PROJECT_TOKEN_PREFIX) :]
    prefix, separator, secret = body.partition(".")
    if not separator or not prefix or not secret or "." in secret:
        return None
    if len(prefix) != 12 or any(char not in "0123456789abcdef" for char in prefix):
        return None
    return prefix, secret


def hash_project_token(token: str, *, pepper: str = "") -> str:
    """Hash a syntactically valid project token for database storage."""

    if parse_project_token(token) is None:
        raise ValueError("malformed project token")
    return _token_digest(token, pepper=pepper)


def verify_project_token(token: str, expected_hash: str, *, pepper: str = "") -> bool:
    """Validate syntax and compare the persisted digest in constant time."""

    if parse_project_token(token) is None:
        return False
    return hmac.compare_digest(hash_project_token(token, pepper=pepper), expected_hash)


def _token_digest(token: str, *, pepper: str) -> str:
    if not isinstance(token, str) or not token:
        raise ValueError("token must be a non-empty string")
    # HMAC permits secret rotation through the application's pepper without
    # changing the token wire format or storing a reversible credential.
    return hmac.new(pepper.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()
