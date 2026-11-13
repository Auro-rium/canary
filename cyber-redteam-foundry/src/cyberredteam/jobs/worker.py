"""Worker process: ``python -m cyberredteam.jobs.worker`` (or ``cyber-rt worker``).

Separate from the API process. Runs procrastinate jobs (campaign runs and the
periodic stale-run reaper) against the Postgres queue.
"""

from __future__ import annotations

import logging

from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.execution import JobRuntime
from cyberredteam.jobs.queue import make_app, make_connector
from cyberredteam.jobs.runner_wiring import make_runner
from cyberredteam.settings import get_settings
from cyberredteam.storage.v2.db import make_session_factory

logger = logging.getLogger(__name__)


async def _placeholder(request, campaign_id):  # replaced by make_runner below
    return None


def build_runtime() -> JobRuntime:
    s = get_settings()
    factory = make_session_factory()
    runtime = JobRuntime(
        factory=factory,
        runner=_placeholder,
        control=DbRunControl(factory, cache_ttl=s.run_control_cache_s),
        heartbeat_interval_s=s.worker_heartbeat_interval_s,
        stale_after_s=s.worker_stale_after_s,
    )
    runtime.runner = make_runner(runtime)
    return runtime


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    connector = make_connector(get_settings().database_url)
    if connector is None:
        raise SystemExit("the worker needs a Postgres DATABASE_URL (postgresql+psycopg://...)")
    app = make_app(connector, build_runtime())
    logger.info("canary worker starting")
    app.run_worker(wait=True)


if __name__ == "__main__":
    main()
