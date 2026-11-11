"""Fernet encryption of short secrets at rest.

The key comes from ``CANARY_ENCRYPTION_KEY`` (``settings.canary_encryption_key``),
a urlsafe-base64 Fernet key. Every failure fails closed with a ``RuntimeError``
whose message never contains the plaintext or the key.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from cyberredteam.settings import get_settings


def _fernet(key: str | None = None) -> Fernet:
    if key is None:
        key = get_settings().canary_encryption_key
    if not key:
        raise RuntimeError("CANARY_ENCRYPTION_KEY is not set; refusing to store or read secrets")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError, AttributeError):
        # Not chained: the original error message could echo key material.
        raise RuntimeError("CANARY_ENCRYPTION_KEY is not a valid Fernet key") from None


def encrypt_str(plaintext: str, key: str | None = None) -> str:
    """Encrypt ``plaintext`` and return the Fernet token as text."""
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a str")
    return _fernet(key).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_str(ciphertext: str, key: str | None = None) -> str:
    """Decrypt a token produced by :func:`encrypt_str`."""
    f = _fernet(key)
    try:
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError, UnicodeError, AttributeError):
        raise RuntimeError("secret could not be decrypted (wrong key or corrupt data)") from None


def generate_key() -> str:
    """Return a fresh Fernet key (for operators and tests)."""
    return Fernet.generate_key().decode("ascii")
