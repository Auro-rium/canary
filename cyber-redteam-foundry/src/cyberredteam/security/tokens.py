"""Per-target ownership verification tokens.

The plaintext token is shown to the operator once; only its digest is stored.
The digest is HMAC-SHA256 with an empty key by default, which in effect is a plain
SHA-256 fingerprint. That is enough here: the token carries 256 bits of
randomness, so the digest cannot be brute-forced. ``pepper`` exists for a
future keyed rollout.
Ported from ``security/tokens.py`` on ``feature/cutc-2026-differential-gate``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

TOKEN_PREFIX = "canary-verify-"


def issue_verification_token() -> str:
    """A high-entropy (256-bit) token, suitable for one-time display."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_verification_token(token: str, *, pepper: str = "") -> str:
    """Keyed SHA-256 digest of ``token``; persist this, never the token."""
    if not isinstance(token, str) or not token:
        raise ValueError("token must be a non-empty string")
    return hmac.new(pepper.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_verification_token(
    candidate: str | None, expected_hash: str | None, *, pepper: str = ""
) -> bool:
    """Constant-time check of ``candidate`` against a stored digest."""
    if not isinstance(candidate, str) or not candidate or not expected_hash:
        return False
    return hmac.compare_digest(hash_verification_token(candidate, pepper=pepper), expected_hash)
