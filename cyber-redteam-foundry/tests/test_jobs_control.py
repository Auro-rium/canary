# ruff: noqa: F811
"""DbRunControl, kill switch and cancel, with fake conversations (no network)."""

from __future__ import annotations

import asyncio

from jobs_support import FakeRunner, db_factory, seed_campaign  # noqa: F401

from cyberredteam.engine.control import RunControl
from cyberredteam.jobs.control import DbRunControl


def _control(factory, ttl=0.0):
    return DbRunControl(factory, cache_ttl=ttl)


def test_implements_protocol(db_factory):
    assert isinstance(_control(db_factory), RunControl)


def test_cancel_and_kill_precedence(db_factory):
    c = _control(db_factory)
    cid = seed_campaign(db_factory)
    other = seed_campaign(db_factory)

    async def go():
        assert await c.check(cid) is None
        c.store.request_cancel(cid, "t")
        assert await c.check(cid) == "cancelled"
        assert await c.check(other) is None
        c.store.set_kill_switch(True, "t")
        assert await c.check(cid) == "killed"  # killed beats cancelled
        assert await c.check(other) == "killed"
        c.store.set_kill_switch(False, "t")
        assert await c.check(other) is None

    asyncio.run(go())


def test_env_kill_switch(db_factory, monkeypatch):
    c = _control(db_factory, ttl=60)
    cid = seed_campaign(db_factory)

    async def go():
        assert await c.check(cid) is None
        monkeypatch.setenv("CANARY_KILL_SWITCH", "1")
        assert await c.check(cid) == "killed"  # uncached, even with a long TTL

    asyncio.run(go())


def test_fails_closed_on_db_error():
    class Boom:
        def __call__(self, *a, **k):
            raise RuntimeError("db down")

    c = DbRunControl(Boom(), cache_ttl=0)
    assert asyncio.run(c.check("any")) == "killed"


def test_fails_closed_when_tables_missing(tmp_path):
    from cyberredteam.storage.v2.db import make_engine, make_session_factory

    engine = make_engine(f"sqlite:///{tmp_path / 'empty.db'}")  # no migration
    c = DbRunControl(make_session_factory(engine), cache_ttl=0)
    assert asyncio.run(c.check("x")) == "killed"


def test_cache_is_short_lived(db_factory):
    now = [0.0]
    c = DbRunControl(db_factory, cache_ttl=1.0, clock=lambda: now[0])
    cid = seed_campaign(db_factory)

    async def go():
        assert await c.check(cid) is None
        c.store.request_cancel(cid, "t")
        assert await c.check(cid) is None  # cached
        now[0] = 1.01
        assert await c.check(cid) == "cancelled"

    asyncio.run(go())


async def _run_ten(db_factory, control, trigger):
    cid = seed_campaign(db_factory)
    runner = FakeRunner(db_factory, control, conversations=10, turns=50, delay=0.02)
    task = asyncio.create_task(runner(None, cid))  # request unused by the fake
    await asyncio.sleep(0.15)
    before = len(runner.sent)
    per_conv_before = {}
    for conv, _ in runner.sent:
        per_conv_before[conv] = per_conv_before.get(conv, 0) + 1
    trigger()
    await asyncio.wait_for(task, 5)
    per_conv_after = {}
    for conv, _ in runner.sent:
        per_conv_after[conv] = per_conv_after.get(conv, 0) + 1
    assert before > 0
    assert len(runner.stopped) == 10
    assert set(runner.stopped.values()) == {"killed"}
    for conv, n in per_conv_after.items():
        # at most the turn already in flight when the switch flipped
        assert n - per_conv_before.get(conv, 0) <= 1, conv


def test_env_kill_switch_stops_ten_conversations(db_factory, monkeypatch):
    c = _control(db_factory)
    asyncio.run(_run_ten(db_factory, c, lambda: monkeypatch.setenv("CANARY_KILL_SWITCH", "1")))


def test_db_kill_switch_stops_ten_conversations(db_factory):
    c = _control(db_factory)
    asyncio.run(_run_ten(db_factory, c, lambda: c.store.set_kill_switch(True, "t")))
