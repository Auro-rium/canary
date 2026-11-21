"""Shared helpers for the WP7 tests (not collected by pytest)."""

from __future__ import annotations

import asyncio
import uuid

import pytest
from cryptography.fernet import Fernet
from storage_v2_support import (
    make_conversation,
    make_policy,
    make_target,
    make_turn,
    migrate_down,
    migrate_up,
    pg_url,
)

from cyberredteam.contracts import CampaignRequest
from cyberredteam.engine.control import RunControl
from cyberredteam.storage.v2.db import make_engine, make_session_factory
from cyberredteam.storage.v2.encrypted import reset_key_cache
from cyberredteam.storage.v2.repositories import (
    CampaignRepo,
    ConversationRepo,
    SqlTargetStore,
)


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgres",
            marks=pytest.mark.skipif(not pg_url(), reason="CANARY_TEST_DATABASE_URL not set"),
        ),
    ]
)
def db_factory(request, tmp_path, monkeypatch):
    """A migrated database (SQLite file, or Postgres when configured) -> sessionmaker."""
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    reset_key_cache()
    monkeypatch.delenv("CANARY_KILL_SWITCH", raising=False)
    url = pg_url() if request.param == "postgres" else f"sqlite:///{tmp_path / 'jobs.db'}"
    if request.param == "postgres":
        migrate_down(url)
    migrate_up(url)
    engine = make_engine(url)
    yield make_session_factory(engine)
    engine.dispose()
    if request.param == "postgres":
        migrate_down(url)


def seed_campaign(
    factory, campaign_id: str | None = None, *, status: str | None = None, org_id: str | None = None
) -> str:
    """Create a verified target (in ``org_id``, if given) and a campaign row; returns the campaign id."""
    store = SqlTargetStore(factory)
    target = make_target()
    target_id = store.create(target, org_id=org_id)
    store.set_verified(target_id, "header")
    cid = campaign_id or f"c-{uuid.uuid4().hex[:8]}"
    repo = CampaignRepo(factory)
    repo.create(cid, target_id, make_policy())
    if status:
        repo.set_status(cid, status)
    return cid


class FakeRunner:
    """Stands in for WP3's run_campaign: N conversations x M turns, persisted,
    calling RunControl.check before every turn and resuming from stored turns."""

    def __init__(self, factory, control: RunControl, conversations=3, turns=5, delay=0.0):
        self.convs = ConversationRepo(factory)
        self.control = control
        self.n_conv = conversations
        self.n_turns = turns
        self.delay = delay
        self.sent: list[tuple[str, int]] = []  # (conversation_id, turn index) actually executed
        self.stopped: dict[str, str] = {}

    async def __call__(self, request: CampaignRequest, campaign_id: str):
        await asyncio.gather(*(self._conv(campaign_id, i) for i in range(self.n_conv)))

    async def _conv(self, campaign_id: str, i: int) -> None:
        cid = f"{campaign_id}-conv{i}"
        existing = await asyncio.to_thread(self.convs.get, cid)
        if existing is None:
            conv = make_conversation(campaign_id, trial=i)
            conv = conv.model_copy(update={"conversation_id": cid})
            await asyncio.to_thread(self.convs.create, conv)
            done = 0
        else:
            done = len(existing.turns)
        for idx in range(done, self.n_turns):
            signal = await self.control.check(campaign_id)
            if signal:
                self.stopped[cid] = signal
                return
            self.sent.append((cid, idx))
            await asyncio.to_thread(self.convs.append_turn, make_turn(cid, idx))
            await asyncio.sleep(self.delay)
