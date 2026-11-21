"""Helpers for the v1 SessionTargetAdapter tests (not collected by pytest)."""

from __future__ import annotations

import uuid

import httpx
import pytest
from cryptography.fernet import Fernet
from storage_v2_support import migrate_up

from cyberredteam.contracts import TargetConfig
from cyberredteam.storage.v2.db import make_engine, make_session_factory
from cyberredteam.storage.v2.encrypted import reset_key_cache
from cyberredteam.storage.v2.repositories import SqlTargetStore
from cyberredteam.tools.target_adapter import SessionTargetAdapter

LOCAL_OK = {"allow_private_targets": True}  # test-only DI, same seam as v2's get_ownership_options


@pytest.fixture
def v1_store(tmp_path, monkeypatch):
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    reset_key_cache()
    url = f"sqlite:///{tmp_path / 'v1.db'}"
    migrate_up(url)
    engine = make_engine(url)
    yield SqlTargetStore(make_session_factory(engine))
    engine.dispose()
    reset_key_cache()


def register(store: SqlTargetStore, endpoint: str, *, verified: bool = True,
             environment: str = "staging") -> TargetConfig:
    cfg = TargetConfig(
        target_id=str(uuid.uuid4()), name="v1-test", endpoint=endpoint,
        session_mode="stateless_history", environment=environment,
    )
    store.create(cfg)
    if verified:
        store.set_verified(cfg.target_id, "test")
    return cfg


def make_transport(reply: dict, seen: list) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=reply)

    return httpx.MockTransport(handler)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def build(store, endpoint, seen, *, verified=True, environment="staging", local=True, **kw):
    """Register (+verify) ``endpoint`` and build an adapter over a mock transport."""
    register(store, endpoint, verified=verified, environment=environment)
    opts = dict(LOCAL_OK) if local else {}
    return SessionTargetAdapter(
        endpoint, store=store, transport=make_transport({"response": "ok"}, seen),
        ownership_options=opts, **kw,
    )
