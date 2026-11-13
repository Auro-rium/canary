"""EncryptedText: round trip, ciphertext at rest, fail-closed key handling."""

from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from sqlalchemy.exc import StatementError

from cyberredteam.storage.v2 import encrypted, orm
from cyberredteam.storage.v2.db import make_engine, make_session_factory, session_scope


@pytest.fixture(autouse=True)
def _fresh_key_cache():
    encrypted.reset_key_cache()
    yield
    encrypted.reset_key_cache()


@pytest.fixture
def key(monkeypatch):
    k = Fernet.generate_key().decode()
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", k)
    return k


@pytest.fixture
def factory(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'enc.db'}")
    orm.Base.metadata.create_all(engine)
    return make_session_factory(engine)


def _seed_conversation(s):
    s.add(orm.TargetRow(
        target_id="t1", name="n", endpoint="https://x.example", auth_public={"type": "none"},
        session_mode="stateless_history", environment="staging",
    ))
    s.flush()
    s.add(orm.CampaignRow(campaign_id="c1", target_id="t1", policy={}))
    s.flush()
    s.add(orm.ConversationRow(conversation_id="v1", campaign_id="c1", technique="x", trial_index=0))


def test_round_trip_and_ciphertext_at_rest(key, factory):
    with session_scope(factory) as s:
        _seed_conversation(s)
        s.add(orm.TurnRow(conversation_id="v1", idx=0, message="super secret ask",
                          response_text="the password is hunter2"))
    with session_scope(factory) as s:
        row = s.query(orm.TurnRow).one()
        assert row.message == "super secret ask"
        assert row.response_text == "the password is hunter2"
        raw = s.execute(text("SELECT message, response_text FROM turns")).one()
    assert "super secret" not in raw[0] and "hunter2" not in raw[1]
    assert Fernet(key.encode()).decrypt(raw[0].encode()) == b"super secret ask"


def test_none_stays_none(key, factory):
    with session_scope(factory) as s:
        _seed_conversation(s)
        s.add(orm.TurnRow(conversation_id="v1", idx=0, message=None, response_text=None))
    with session_scope(factory) as s:
        assert s.query(orm.TurnRow).one().message is None
        assert s.execute(text("SELECT message FROM turns")).scalar() is None


def test_missing_key_fails_closed(monkeypatch, factory, key):
    with session_scope(factory) as s:
        _seed_conversation(s)
        s.add(orm.TurnRow(conversation_id="v1", idx=0, message="m", response_text="r"))
    encrypted.reset_key_cache()
    monkeypatch.setattr(encrypted, "get_settings", lambda: SimpleNamespace(canary_encryption_key=None))
    with pytest.raises((RuntimeError, StatementError), match="CANARY_ENCRYPTION_KEY") as ei:
        with session_scope(factory) as s:
            s.add(orm.TurnRow(conversation_id="v1", idx=1, message="m-PLAINTEXT", response_text="r"))
    assert "m-PLAINTEXT" not in str(ei.value)  # hide_parameters: no evidence in errors
    with pytest.raises(RuntimeError, match="CANARY_ENCRYPTION_KEY"):
        with session_scope(factory) as s:
            s.query(orm.TurnRow).all()
    with session_scope(factory) as s:  # nothing was stored in plaintext either
        assert s.execute(text("SELECT count(*) FROM turns")).scalar() == 1


def test_invalid_key_fails_closed(monkeypatch):
    monkeypatch.setattr(encrypted, "get_settings", lambda: SimpleNamespace(canary_encryption_key="nope"))
    with pytest.raises(RuntimeError, match="valid Fernet key"):
        encrypted.get_fernet()


def test_wrong_key_cannot_decrypt(monkeypatch, factory, key):
    with session_scope(factory) as s:
        _seed_conversation(s)
        s.add(orm.TurnRow(conversation_id="v1", idx=0, message="m", response_text="r"))
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    encrypted.reset_key_cache()
    with pytest.raises(RuntimeError, match="could not be decrypted"):
        with session_scope(factory) as s:
            s.query(orm.TurnRow).all()


def test_settings_read_once_until_reset(monkeypatch):
    calls = []
    k = Fernet.generate_key().decode()

    def fake():
        calls.append(1)
        return SimpleNamespace(canary_encryption_key=k)

    monkeypatch.setattr(encrypted, "get_settings", fake)
    encrypted.get_fernet()
    encrypted.get_fernet()
    assert len(calls) == 1
    encrypted.reset_key_cache()
    encrypted.get_fernet()
    assert len(calls) == 2
