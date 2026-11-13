# ruff: noqa: F811
"""Queue, execution, heartbeat/reaper and resume, plus migration 0002."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from alembic import command
from jobs_support import FakeRunner, db_factory, seed_campaign  # noqa: F401
from procrastinate.testing import InMemoryConnector
from sqlalchemy import inspect
from storage_v2_support import alembic_config, migrate_down, migrate_up, pg_url

from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.events import EventLog
from cyberredteam.jobs.execution import JobRuntime, execute_campaign, load_request
from cyberredteam.jobs.queue import (
    TASK_RUN_CAMPAIGN,
    InProcessQueue,
    ProcrastinateQueue,
    enqueue_campaign,
    make_app,
)
from cyberredteam.jobs.resume import HeartbeatRepo, reap_stale
from cyberredteam.storage.v2.db import make_engine
from cyberredteam.storage.v2.orm import utcnow
from cyberredteam.storage.v2.repositories import AuditRepo, CampaignRepo, ConversationRepo


def _runtime(factory, **fake_kw):
    control = DbRunControl(factory, cache_ttl=0)
    runner = FakeRunner(factory, control, **fake_kw)
    return JobRuntime(factory=factory, runner=runner, control=control, heartbeat_interval_s=0.05), runner


def test_execute_runs_to_completion_and_emits_events(db_factory):
    rt, runner = _runtime(db_factory, conversations=2, turns=3)
    cid = seed_campaign(db_factory)
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    assert CampaignRepo(db_factory).get(cid).status == "completed"
    assert len(runner.sent) == 6
    types = [e.type for e in EventLog(db_factory).since(cid)]
    assert types == ["campaign_started", "campaign_completed"]
    assert HeartbeatRepo(db_factory).get(cid) is None  # released
    # finished campaigns are skipped on re-delivery
    assert asyncio.run(execute_campaign(rt, cid)) == "skipped"


def test_load_request_refuses_unverified_target(db_factory):
    rt, _ = _runtime(db_factory)
    cid = seed_campaign(db_factory)
    rec = CampaignRepo(db_factory).get(cid)
    from sqlalchemy import update

    from cyberredteam.storage.v2 import orm
    from cyberredteam.storage.v2.repositories import SqlTargetStore

    with db_factory() as s:
        s.execute(update(orm.TargetRow).where(orm.TargetRow.target_id == rec.target_id).values(verified=False))
        s.commit()
    assert SqlTargetStore(db_factory).get(rec.target_id).verified is False
    assert asyncio.run(execute_campaign(rt, cid)) == "failed"
    assert CampaignRepo(db_factory).get(cid).status == "failed"


def test_runner_exception_marks_failed(db_factory):
    rt, _ = _runtime(db_factory)

    async def boom(request, campaign_id):
        raise ValueError("secret-in-message")

    rt.runner = boom
    cid = seed_campaign(db_factory)
    assert asyncio.run(execute_campaign(rt, cid)) == "failed"
    ev = EventLog(db_factory).since(cid)[-1]
    assert ev.type == "campaign_failed" and ev.payload["error"] == "ValueError"
    assert "secret" not in str(ev.payload)


def test_kill_during_execution_marks_failed_and_audits(db_factory):
    rt, runner = _runtime(db_factory, conversations=3, turns=50, delay=0.02)
    cid = seed_campaign(db_factory)

    async def go():
        t = asyncio.create_task(execute_campaign(rt, cid))
        await asyncio.sleep(0.15)
        rt.control.store.set_kill_switch(True, "t")
        return await asyncio.wait_for(t, 5)

    assert asyncio.run(go()) == "failed"
    assert EventLog(db_factory).since(cid)[-1].type == "campaign_killed"
    assert AuditRepo(db_factory).list(action="campaign.killed")


def test_cancel_before_start(db_factory):
    rt, runner = _runtime(db_factory)
    cid = seed_campaign(db_factory)
    rt.control.store.request_cancel(cid, "t")
    assert asyncio.run(execute_campaign(rt, cid)) == "cancelled"
    assert runner.sent == []


def test_reaper_reenqueues_stale_and_resume_skips_finished_turns(db_factory):
    # First run is interrupted mid-way (simulated crash: kill, then reset to running).
    rt, runner = _runtime(db_factory, conversations=3, turns=20, delay=0.01)
    cid = seed_campaign(db_factory)

    async def first():
        t = asyncio.create_task(execute_campaign(rt, cid))
        await asyncio.sleep(0.12)
        rt.control.store.set_kill_switch(True, "t")
        await t
        rt.control.store.set_kill_switch(False, "t")

    asyncio.run(first())
    done_before = set(runner.sent)
    assert 0 < len(done_before) < 60
    with db_factory() as s:  # the "crashed worker" left status running, no heartbeat
        from cyberredteam.storage.v2 import orm

        s.get(orm.CampaignRow, cid).status = "running"
        s.commit()
    beats = HeartbeatRepo(db_factory)
    assert beats.stale_running(5.0) == [cid]

    queue = InProcessQueue(rt)

    async def reap_and_run():
        assert await reap_stale(db_factory, queue, 5.0) == [cid]
        await queue.drain()
        # reaper claimed it: a second tick does not duplicate
        assert await reap_stale(db_factory, queue, 5.0) == []

    asyncio.run(reap_and_run())
    assert queue.enqueued == [cid]
    assert CampaignRepo(db_factory).get(cid).status == "completed"
    runs = [x for x in runner.sent]
    assert len(runs) == len(set(runs)) == 60  # every turn exactly once across both runs
    assert AuditRepo(db_factory).list(action="campaign.resume_enqueued")
    convs = ConversationRepo(db_factory)
    assert all(len(convs.get(f"{cid}-conv{i}").turns) == 20 for i in range(3))
    assert "campaign_resumed" in [e.type for e in EventLog(db_factory).since(cid)]


def test_reaper_ignores_fresh_heartbeat_and_respects_kill_switch(db_factory, monkeypatch):
    rt, _ = _runtime(db_factory)
    cid = seed_campaign(db_factory, status="running")
    beats = HeartbeatRepo(db_factory)
    beats.beat(cid, "w1")
    queue = InProcessQueue()
    assert asyncio.run(reap_stale(db_factory, queue, 60)) == []
    # stale heartbeat, but kill switch on -> nothing enqueued
    with db_factory() as s:
        from cyberredteam.jobs.tables import CampaignHeartbeatRow

        s.get(CampaignHeartbeatRow, cid).beat_at = utcnow() - timedelta(seconds=600)
        s.commit()
    rt.control.store.set_kill_switch(True, "t")
    assert asyncio.run(reap_stale(db_factory, queue, 60)) == []
    rt.control.store.set_kill_switch(False, "t")
    assert asyncio.run(reap_stale(db_factory, queue, 60)) == [cid]


def test_live_worker_blocks_second_claim(db_factory):
    cid = seed_campaign(db_factory)
    beats = HeartbeatRepo(db_factory)
    assert beats.claim(cid, "w1", 45) is True
    assert beats.claim(cid, "w2", 45) is False
    assert beats.claim(cid, "w1", 45) is True
    assert beats.claim(cid, "w2", 0) is True  # w1's heartbeat now counts as stale


def test_procrastinate_in_memory_roundtrip(db_factory):
    rt, runner = _runtime(db_factory, conversations=2, turns=2)
    cid = seed_campaign(db_factory)
    connector = InMemoryConnector()
    app = make_app(connector, rt)

    async def go():
        q = ProcrastinateQueue(app)
        await enqueue_campaign(cid, q)
        await enqueue_campaign(cid, q)  # duplicate while queued is a no-op
        assert len(connector.jobs) == 1
        job = next(iter(connector.jobs.values()))
        assert job["task_name"] == TASK_RUN_CAMPAIGN and job["lock"] == cid
        await app.run_worker_async(wait=False, install_signal_handlers=False)
        await q.close()

    asyncio.run(go())
    assert CampaignRepo(db_factory).get(cid).status == "completed"
    assert len(runner.sent) == 4


def test_load_request_builds_validated_request(db_factory):
    rt, _ = _runtime(db_factory)
    cid = seed_campaign(db_factory)
    req = load_request(rt, cid)
    assert req.target.verified and req.policy.techniques == ["prompt_injection"]


# ── migration 0002 ───────────────────────────────────────────────────────────

NEW = {"run_control", "campaign_heartbeats", "campaign_events"}


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(
    not pg_url(), reason="CANARY_TEST_DATABASE_URL not set"))])
def mig_url(request, tmp_path):
    u = pg_url() if request.param == "postgres" else f"sqlite:///{tmp_path / 'm.db'}"
    if request.param == "postgres":
        migrate_down(u)
    yield u
    if request.param == "postgres":
        migrate_down(u)


def test_migration_0002_up_down(mig_url):
    engine = make_engine(mig_url)
    cfg = alembic_config(mig_url)
    command.upgrade(cfg, "0001")
    assert not NEW & set(inspect(engine).get_table_names())
    command.upgrade(cfg, "0002")
    assert NEW <= set(inspect(engine).get_table_names())
    command.downgrade(cfg, "0001")
    tables = set(inspect(engine).get_table_names())
    assert not NEW & tables and "campaigns" in tables
    migrate_up(mig_url)
    assert NEW <= set(inspect(engine).get_table_names())
    migrate_down(mig_url)
    assert not NEW & set(inspect(engine).get_table_names())
    engine.dispose()
