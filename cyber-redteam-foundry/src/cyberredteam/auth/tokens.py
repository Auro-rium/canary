"""API key, session and CSRF token helpers (WP8).

* API keys look like ``cnry_<key_id>_<secret>``. ``key_id`` is a public lookup
  prefix; only ``sha256(full key)`` is stored. Keys are 256-bit random, so a
  fast hash is sufficient (no password-style KDF needed).
* Comparisons use :func:`hmac.compare_digest` (constant time).
* Session and CSRF tokens are random URL-safe strings, stored hashed.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

API_KEY_PREFIX = "cnry"
_KEY_RE = re.compile(r"^cnry_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$")
# Compared against when a key id is unknown, so the unknown path costs the same.
_DUMMY_HASH = hashlib.sha256(b"canary-dummy-api-key").hexdigest()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_api_key() -> tuple[str, str, str]:
    """Return ``(key_id, full_key, key_hash)``. The full key is shown once, never stored."""
    key_id = secrets.token_hex(8)
    full = f"{API_KEY_PREFIX}_{key_id}_{secrets.token_urlsafe(32)}"
    return key_id, full, sha256_hex(full)


def parse_api_key(value: str) -> str | None:
    """The ``key_id`` of a well-formed key, else ``None``."""
    m = _KEY_RE.match(value or "")
    return m.group(1) if m else None


def key_matches(presented: str, stored_hash: str | None) -> bool:
    """Constant-time check of a presented key against a stored hash.

    With ``stored_hash=None`` (unknown key id) a dummy comparison still runs and
    the result is False.
    """
    expected = stored_hash if stored_hash else _DUMMY_HASH
    ok = hmac.compare_digest(sha256_hex(presented).encode(), expected.encode())
    return ok and stored_hash is not None


def new_token() -> tuple[str, str]:
    """Return ``(token, sha256 hex)`` for sessions, CSRF tokens and OIDC state."""
    token = secrets.token_urlsafe(32)
    return token, sha256_hex(token)


def token_matches(presented: str | None, stored_hash: str | None) -> bool:
    if not presented or not stored_hash:
        return False
    return hmac.compare_digest(sha256_hex(presented).encode(), stored_hash.encode())
