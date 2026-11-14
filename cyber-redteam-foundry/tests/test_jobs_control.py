"""DbRunControl, kill switch and cancel, with fake conversations (no network)."""

from __future__ import annotations

import asyncio

import pytest
from jobs_support import FakeRunner, seed_campaign

from cyberredteam.engine.control import RunControl
from cyberredteam.jobs.control import DbRunControl, env_kill_switch_active
from cyberredteam.settings import get_settings


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


def test_production_default_is_uncached():
    assert get_settings().run_control_cache_s == 0.0
    assert DbRunControl(None)._ttl == 0.0


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", "anything", " 2 "])
def test_env_kill_switch_fails_safe_truthy(monkeypatch, value):
    monkeypatch.setenv("CANARY_KILL_SWITCH", value)
    assert env_kill_switch_active() is True


@pytest.mark.parametrize("value", ["", "0", "false", "False", "no", "off", "  "])
def test_env_kill_switch_falsy(monkeypatch, value):
    monkeypatch.setenv("CANARY_KILL_SWITCH", value)
    assert env_kill_switch_active() is False


def test_env_kill_switch_unset(monkeypatch):
    monkeypatch.delenv("CANARY_KILL_SWITCH", raising=False)
    assert env_kill_switch_active() is False


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


def _prod_control(db_factory):
    """DbRunControl exactly as the worker builds it (production settings)."""
    return DbRunControl(db_factory, cache_ttl=get_settings().run_control_cache_s)


def test_env_kill_switch_stops_ten_conversations(db_factory, monkeypatch):
    c = _prod_control(db_factory)
    asyncio.run(_run_ten(db_factory, c, lambda: monkeypatch.setenv("CANARY_KILL_SWITCH", "1")))


def test_db_kill_switch_stops_ten_conversations(db_factory):
    c = _prod_control(db_factory)
    asyncio.run(_run_ten(db_factory, c, lambda: c.store.set_kill_switch(True, "t")))


def test_cancel_stops_ten_conversations_with_production_settings(db_factory):
    c = _prod_control(db_factory)

    async def go():
        cid = seed_campaign(db_factory)
        runner = FakeRunner(db_factory, c, conversations=10, turns=60, delay=0.005)
        task = asyncio.create_task(runner(None, cid))
        await asyncio.sleep(0.1)
        before = len(runner.sent)
        c.store.request_cancel(cid, "t")
        await asyncio.wait_for(task, 5)
        assert before > 0 and set(runner.stopped.values()) == {"cancelled"}
        assert len(runner.stopped) == 10
        assert len(runner.sent) - before <= 10  # at most one in-flight turn per conversation

    asyncio.run(go())
