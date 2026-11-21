"""Worker process: ``python -m cyberredteam.jobs.worker`` (or ``cyber-rt worker``).

Separate from the API process. Runs procrastinate jobs (campaign runs and the
periodic stale-run reaper) against the Postgres queue.
"""

from __future__ import annotations

import logging

from cyberredteam.engine import PlannerFactory
from cyberredteam.jobs.control import ControlStore, DbRunControl, env_kill_switch_active
from cyberredteam.jobs.execution import JobRuntime
from cyberredteam.jobs.queue import make_app, make_connector
from cyberredteam.jobs.runner_wiring import load_planner_factory, make_runner
from cyberredteam.observability.setup import init_observability
from cyberredteam.settings import get_settings
from cyberredteam.storage.v2.db import make_session_factory

logger = logging.getLogger(__name__)


async def _placeholder(request, campaign_id):  # replaced by make_runner below
    return None


def build_runtime(planner_factory: PlannerFactory | None = None) -> JobRuntime:
    s = get_settings()
    factory = make_session_factory()
    runtime = JobRuntime(
        factory=factory,
        runner=_placeholder,
        control=DbRunControl(factory, cache_ttl=s.run_control_cache_s),
        heartbeat_interval_s=s.worker_heartbeat_interval_s,
        stale_after_s=s.worker_stale_after_s,
    )
    if planner_factory is None:
        planner_factory = load_planner_factory(s.planner_factory)
    runtime.runner = make_runner(runtime, planner_factory)
    return runtime


def observability_providers(factory) -> dict:
    """Zero-arg gauges for ``ServiceReporter`` (called on its thread; a provider
    that raises is skipped for that tick)."""
    from sqlalchemy import func, select, text

    from cyberredteam.storage.v2 import orm
    from cyberredteam.storage.v2.db import session_scope

    def queue_depth() -> float:
        with session_scope(factory) as s:
            return float(
                s.execute(text("SELECT count(*) FROM procrastinate_jobs WHERE status = 'todo'")).scalar_one()
            )

    def active_campaigns() -> float:
        with session_scope(factory) as s:
            return float(
                s.scalar(select(func.count()).select_from(orm.CampaignRow).where(orm.CampaignRow.status == "running"))
                or 0
            )

    def kill_switch() -> float:
        return 1.0 if (env_kill_switch_active() or ControlStore(factory).kill_switch_state()[0]) else 0.0

    return {"queue_depth": queue_depth, "active_campaigns": active_campaigns, "kill_switch": kill_switch}


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    s = get_settings()
    connector = make_connector(s.database_url)
    if connector is None:
        raise SystemExit("the worker needs a Postgres DATABASE_URL (postgresql+psycopg://...)")
    runtime = build_runtime()
    # No-op unless WANDB_API_KEY (or offline mode) is set; never raises.
    init_observability(s, service_name="worker", providers=observability_providers(runtime.factory))
    app = make_app(connector, runtime)
    logger.info("canary worker starting")
    app.run_worker(wait=True, shutdown_graceful_timeout=s.worker_shutdown_graceful_s)


if __name__ == "__main__":
    main()
