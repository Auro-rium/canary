"""Fernet-encrypted text column (evidence and target secrets at rest).

Key semantics match the rest of the platform: ``Settings.canary_encryption_key``
is a urlsafe-base64 Fernet key. A missing or malformed key raises
``RuntimeError`` (fail closed): nothing is ever stored or read in plaintext.
"""

from __future__ import annotations

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

from cyberredteam.settings import get_settings


@lru_cache(maxsize=8)
def _fernet_for(key: str) -> Fernet:
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("CANARY_ENCRYPTION_KEY is not a valid Fernet key") from exc


def get_fernet() -> Fernet:
    key = get_settings().canary_encryption_key
    if not key:
        raise RuntimeError(
            "CANARY_ENCRYPTION_KEY is not set; refusing to store or read encrypted data"
        )
    return _fernet_for(key)


class EncryptedText(TypeDecorator):
    """Text stored as a Fernet token. ``None`` stays ``None``."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return get_fernet().encrypt(str(value).encode("utf-8")).decode("ascii")

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return get_fernet().decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise RuntimeError("stored value could not be decrypted (wrong key?)") from exc
