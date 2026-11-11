"""Fernet secret encryption: round-trip and fail-closed behaviour."""

import pytest

from cyberredteam.security import crypto


@pytest.fixture
def key(monkeypatch):
    k = crypto.generate_key()
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", k)
    return k


def test_round_trip(key):
    token = crypto.encrypt_str("hunter2-secret")
    assert "hunter2" not in token
    assert crypto.decrypt_str(token) == "hunter2-secret"


def test_explicit_key_round_trip():
    k = crypto.generate_key()
    assert crypto.decrypt_str(crypto.encrypt_str("x", key=k), key=k) == "x"


def test_missing_key_fails_closed(monkeypatch):
    monkeypatch.delenv("CANARY_ENCRYPTION_KEY", raising=False)
    # Also guard against a stray .env file supplying a key.
    monkeypatch.setattr(
        crypto, "get_settings", lambda: type("S", (), {"canary_encryption_key": None})()
    )
    with pytest.raises(RuntimeError, match="not set"):
        crypto.encrypt_str("secret")
    with pytest.raises(RuntimeError):
        crypto.decrypt_str("anything")


def test_invalid_key_fails_closed(monkeypatch):
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", "not-a-fernet-key")
    with pytest.raises(RuntimeError, match="not a valid Fernet key") as exc:
        crypto.encrypt_str("secret")
    assert "not-a-fernet-key" not in str(exc.value)


def test_wrong_key_cannot_decrypt(key):
    token = crypto.encrypt_str("secret-value")
    with pytest.raises(RuntimeError) as exc:
        crypto.decrypt_str(token, key=crypto.generate_key())
    assert "secret-value" not in str(exc.value)


def test_corrupt_ciphertext_fails_closed(key):
    with pytest.raises(RuntimeError):
        crypto.decrypt_str("garbage")
