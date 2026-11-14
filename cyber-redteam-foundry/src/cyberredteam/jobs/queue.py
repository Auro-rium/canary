"""Queue layer: procrastinate (Postgres) in production, in-process for tests/dev.

The API process only *enqueues*; worker processes run ``execute_campaign``.
``JobQueue`` is the seam: tests use :class:`InProcessQueue` or procrastinate's
``InMemoryConnector``, neither needs a running worker or database.

One job per campaign: ``queueing_lock=campaign_id`` makes a duplicate enqueue a
no-op while one is waiting. There is deliberately NO procrastinate ``lock``: a
SIGKILLed worker leaves its job in ``doing`` holding the lock, which would block
the resume job forever. Run exclusivity is the heartbeat claim
(``jobs/resume.py``). The reaper also finishes such stalled ``doing`` jobs
(:func:`finish_stalled_jobs`) so they do not linger.

procrastinate is pinned (``~=3.11.0``): its schema is applied by
``jobs/migrate.py`` only when missing, so upgrading procrastinate requires
applying its schema migrations (``procrastinate schema --apply`` equivalents)
as a separate, deliberate step.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Protocol

import procrastinate
from procrastinate import exceptions as pexc
from procrastinate import jobs as pjobs

from cyberredteam.jobs.execution import JobRuntime, execute_campaign

logger = logging.getLogger(__name__)

TASK_RUN_CAMPAIGN = "canary.run_campaign"
TASK_REAP_STALE = "canary.reap_stale"


class JobQueue(Protocol):
    async def enqueue_campaign(self, campaign_id: str) -> bool:
        """Enqueue a run. Returns True if a job was enqueued, False if one was already waiting."""
        ...


def pg_conninfo(database_url: str) -> str:
    """SQLAlchemy URL -> libpq URL (strip the ``+psycopg`` driver suffix)."""
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def make_connector(database_url: str | None) -> procrastinate.BaseConnector | None:
    """PsycopgConnector for Postgres URLs; ``None`` otherwise (sqlite dev/tests)."""
    if database_url and database_url.startswith("postgresql"):
        return procrastinate.PsycopgConnector(conninfo=pg_conninfo(database_url))
    return None


async def finish_stalled_jobs(app: procrastinate.App, seconds_since_heartbeat: float = 30) -> int:
    """Mark ``doing`` run jobs whose worker stopped heartbeating as failed.

    The campaign itself is resumed by the reaper via a fresh job.
    """
    manager = app.job_manager
    stalled = await manager.get_stalled_jobs(
        task_name=TASK_RUN_CAMPAIGN, seconds_since_heartbeat=seconds_since_heartbeat
    )
    for job in stalled:
        await manager.finish_job_by_id_async(job.id, status=pjobs.Status.FAILED, delete_job=False)
        logger.warning("finished stalled job id=%s", job.id)
    return len(list(stalled))


def make_app(
    connector: procrastinate.BaseConnector, runtime: JobRuntime | None = None
) -> procrastinate.App:
    """Build a procrastinate app. With a ``runtime`` it also registers the worker tasks."""
    app = procrastinate.App(connector=connector)
    if runtime is None:
        return app

    @app.task(name=TASK_RUN_CAMPAIGN)
    async def run_campaign_job(campaign_id: str) -> str:
        return await execute_campaign(runtime, campaign_id)

    @app.periodic(cron="* * * * *")
    @app.task(name=TASK_REAP_STALE, queueing_lock="canary-reaper")
    async def reap_stale_job(timestamp: int) -> list[str]:
        from cyberredteam.jobs.resume import reap_stale

        try:
            await finish_stalled_jobs(app, runtime.stale_after_s)
        except Exception as exc:
            logger.error("stalled job cleanup failed (%s)", type(exc).__name__)
        result = await reap_stale(
            runtime.factory, ProcrastinateQueue(app, assume_open=True), runtime.stale_after_s
        )
        return result.resumed + result.cancelled

    return app


class ProcrastinateQueue:
    def __init__(self, app: procrastinate.App, *, assume_open: bool = False) -> None:
        self._app = app
        self._open = assume_open
        self._lock = asyncio.Lock()

    async def _ensure_open(self) -> None:
        async with self._lock:
            if not self._open:
                await self._app.open_async()
                self._open = True

    async def close(self) -> None:
        if self._open:
            await self._app.close_async()
            self._open = False

    async def enqueue_campaign(self, campaign_id: str) -> bool:
        await self._ensure_open()
        try:
            await self._app.configure_task(
                TASK_RUN_CAMPAIGN, queueing_lock=campaign_id
            ).defer_async(campaign_id=campaign_id)
        except pexc.AlreadyEnqueued:
            logger.info("campaign %s already queued", campaign_id)
            return False
        return True


class InProcessQueue:
    """Records enqueues; with a ``runtime`` it also runs them in this event loop."""

    def __init__(self, runtime: JobRuntime | None = None) -> None:
        self.enqueued: list[str] = []
        self._runtime = runtime
        self._tasks: list[asyncio.Task[Any]] = []

    async def enqueue_campaign(self, campaign_id: str) -> bool:
        self.enqueued.append(campaign_id)
        if self._runtime is not None:
            self._tasks.append(asyncio.create_task(execute_campaign(self._runtime, campaign_id)))
        return True

    async def drain(self) -> None:
        await asyncio.gather(*self._tasks)


_default_queue: JobQueue | None = None


def set_default_queue(queue: JobQueue | None) -> None:
    global _default_queue
    _default_queue = queue


def get_default_queue() -> JobQueue:
    """Default queue: procrastinate on Postgres, else an in-process recorder."""
    global _default_queue
    if _default_queue is None:
        from cyberredteam.settings import get_settings

        connector = make_connector(get_settings().database_url)
        if connector is None:
            logger.warning(
                "DATABASE_URL is not Postgres: using the in-process queue, which only RECORDS "
                "enqueues and never runs them. Dev/tests only; production needs Postgres + a worker."
            )
            _default_queue = InProcessQueue()
        else:
            _default_queue = ProcrastinateQueue(make_app(connector))
    return _default_queue


async def enqueue_campaign(campaign_id: str, queue: JobQueue | None = None) -> bool:
    """Enqueue a campaign run (idempotent while one is queued)."""
    return await (queue or get_default_queue()).enqueue_campaign(campaign_id)
