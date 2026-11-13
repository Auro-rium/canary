"""Queue layer: procrastinate (Postgres) in production, in-process for tests/dev.

The API process only *enqueues*; worker processes run ``execute_campaign``.
``JobQueue`` is the seam: tests use :class:`InProcessQueue` or procrastinate's
``InMemoryConnector``, neither needs a running worker or database.

One job per campaign: ``lock=campaign_id`` serialises runs and
``queueing_lock=campaign_id`` makes a duplicate enqueue a no-op while one is
still waiting.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Protocol

import procrastinate
from procrastinate import exceptions as pexc

from cyberredteam.jobs.execution import JobRuntime, execute_campaign

logger = logging.getLogger(__name__)

TASK_RUN_CAMPAIGN = "canary.run_campaign"
TASK_REAP_STALE = "canary.reap_stale"


class JobQueue(Protocol):
    async def enqueue_campaign(self, campaign_id: str) -> None: ...


def pg_conninfo(database_url: str) -> str:
    """SQLAlchemy URL -> libpq URL (strip the ``+psycopg`` driver suffix)."""
    return database_url.replace("postgresql+psycopg://", "postgresql://", 1)


def make_connector(database_url: str | None) -> procrastinate.BaseConnector | None:
    """PsycopgConnector for Postgres URLs; ``None`` otherwise (sqlite dev/tests)."""
    if database_url and database_url.startswith("postgresql"):
        return procrastinate.PsycopgConnector(conninfo=pg_conninfo(database_url))
    return None


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

        return await reap_stale(runtime.factory, ProcrastinateQueue(app), runtime.stale_after_s)

    return app


class ProcrastinateQueue:
    def __init__(self, app: procrastinate.App) -> None:
        self._app = app
        self._open = False
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

    async def enqueue_campaign(self, campaign_id: str) -> None:
        await self._ensure_open()
        try:
            await self._app.configure_task(
                TASK_RUN_CAMPAIGN, lock=campaign_id, queueing_lock=campaign_id
            ).defer_async(campaign_id=campaign_id)
        except pexc.AlreadyEnqueued:
            logger.info("campaign %s already queued", campaign_id)


class InProcessQueue:
    """Records enqueues; with a ``runtime`` it also runs them in this event loop."""

    def __init__(self, runtime: JobRuntime | None = None) -> None:
        self.enqueued: list[str] = []
        self._runtime = runtime
        self._tasks: list[asyncio.Task[Any]] = []

    async def enqueue_campaign(self, campaign_id: str) -> None:
        self.enqueued.append(campaign_id)
        if self._runtime is not None:
            self._tasks.append(asyncio.create_task(execute_campaign(self._runtime, campaign_id)))

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
        _default_queue = (
            ProcrastinateQueue(make_app(connector)) if connector is not None else InProcessQueue()
        )
    return _default_queue


async def enqueue_campaign(campaign_id: str, queue: JobQueue | None = None) -> None:
    """Enqueue a campaign run (idempotent while one is queued)."""
    await (queue or get_default_queue()).enqueue_campaign(campaign_id)
