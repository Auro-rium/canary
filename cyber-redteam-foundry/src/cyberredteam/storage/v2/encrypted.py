"""Fernet-encrypted text column (evidence and target secrets at rest).

Key semantics match the rest of the platform: ``Settings.canary_encryption_key``
is a urlsafe-base64 Fernet key. A missing or malformed key raises
``RuntimeError`` (fail closed): nothing is ever stored or read in plaintext.
"""

from __future__ import annotations

from cryptography.fernet import Fernet
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from cyberredteam.security import crypto
from cyberredteam.settings import get_settings


_cached_key: str | None = None


def reset_key_cache() -> None:
    """Forget the cached key (tests, or after rotating CANARY_ENCRYPTION_KEY)."""
    global _cached_key
    _cached_key = None


def _configured_key() -> str:
    """The configured key, read from settings once per process (until
    ``reset_key_cache``); a missing key is never cached, so it fails closed."""
    global _cached_key
    if _cached_key is None:
        key = get_settings().canary_encryption_key
        if not key:
            raise RuntimeError(
                "CANARY_ENCRYPTION_KEY is not set; refusing to store or read encrypted data"
            )
        _cached_key = key
    return _cached_key


def get_fernet() -> Fernet:
    """Fernet for the configured key (validated by ``security.crypto``)."""
    return crypto.fernet_for_key(_configured_key())


class EncryptedText(TypeDecorator):
    """Text stored as a Fernet token. ``None`` stays ``None``."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return crypto.encrypt_str(str(value), key=_configured_key())

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return crypto.decrypt_str(value, key=_configured_key())
