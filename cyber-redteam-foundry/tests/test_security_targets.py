"""InMemoryTargetStore: secrets encrypted at rest, verified only via set_verified."""

import uuid

import pytest

from cyberredteam.contracts import TargetConfig
from cyberredteam.security import crypto
from cyberredteam.security.targets import InMemoryTargetStore, TargetStore


@pytest.fixture
def key(monkeypatch):
    k = crypto.generate_key()
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", k)
    return k


def make(auth=None, **kw):
    data = {
        "target_id": str(uuid.uuid4()),
        "name": "agent",
        "endpoint": "https://agent.example.com/chat",
        "session_mode": "stateless_history",
        "environment": "staging",
        "auth": auth or {"type": "none"},
    }
    data.update(kw)
    return TargetConfig.model_validate(data)


def test_implements_protocol():
    assert isinstance(InMemoryTargetStore(), TargetStore)


@pytest.mark.parametrize(
    "auth, secret",
    [
        ({"type": "bearer", "token": "tok-SECRET-1"}, "tok-SECRET-1"),
        ({"type": "header", "header_name": "X-Api-Key", "value": "hdr-SECRET-2"}, "hdr-SECRET-2"),
        (
            {
                "type": "oauth_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id": "cid",
                "client_secret": "oauth-SECRET-3",
            },
            "oauth-SECRET-3",
        ),
        (
            {
                "type": "cookie_login",
                "login_url": "https://agent.example.com/login",
                "username": "u",
                "password": "pw-SECRET-4",
            },
            "pw-SECRET-4",
        ),
    ],
)
def test_round_trip_and_encrypted_at_rest(key, auth, secret):
    store = InMemoryTargetStore()
    cfg = make(auth)
    tid = store.create(cfg)
    assert tid == cfg.target_id
    record = store._records[tid]
    assert secret not in repr(record.__dict__)
    assert record.auth_secrets_enc  # ciphertext held
    got = store.get(tid)
    assert got == cfg
    revealed = [
        getattr(got.auth, k).get_secret_value()
        for k in type(got.auth).model_fields
        if hasattr(getattr(got.auth, k), "get_secret_value")
    ]
    assert revealed == [secret]
    assert secret not in got.model_dump_json()


def test_create_ignores_verified_flag(key):
    store = InMemoryTargetStore()
    tid = store.create(make(verified=True))
    assert store.get(tid).verified is False
    store.set_verified(tid, "dns_txt")
    assert store.get(tid).verified is True
    assert store._records[tid].verified_method == "dns_txt"


def test_missing_key_fails_closed_for_secrets(monkeypatch):
    monkeypatch.setattr(
        crypto, "get_settings", lambda: type("S", (), {"canary_encryption_key": None})()
    )
    store = InMemoryTargetStore()
    with pytest.raises(RuntimeError):
        store.create(make({"type": "bearer", "token": "t"}))
    assert store.list() == []


def test_duplicate_and_unknown_ids(key):
    store = InMemoryTargetStore()
    cfg = make()
    store.create(cfg)
    with pytest.raises(ValueError):
        store.create(cfg)
    assert store.get(str(uuid.uuid4())) is None
    with pytest.raises(KeyError):
        store.set_verified("nope", "dns_txt")
    with pytest.raises(KeyError):
        store.set_verification_token_hash("nope", "h")
    assert store.get_verification_token_hash("nope") is None


def test_token_hash_and_list(key):
    store = InMemoryTargetStore()
    a, b = make(), make()
    store.create(a)
    store.create(b)
    store.set_verification_token_hash(a.target_id, "abc")
    assert store.get_verification_token_hash(a.target_id) == "abc"
    assert store.get_verification_token_hash(b.target_id) is None
    assert {t.target_id for t in store.list()} == {a.target_id, b.target_id}


def test_explicit_key_constructor():
    store = InMemoryTargetStore(encryption_key=crypto.generate_key())
    tid = store.create(make({"type": "bearer", "token": "abc"}))
    assert store.get(tid).auth.token.get_secret_value() == "abc"
