"""RQ worker entrypoint for release evaluations.

Workers load release metadata from the durable database and then invoke the
existing LangGraph release runner. No campaign lifecycle is held by the API
process. The import of ``api`` is intentionally inside the job function to
avoid importing FastAPI while RQ discovers this module.
"""

from __future__ import annotations

import logging

from cyberredteam.schemas import StrategyType
from cyberredteam.settings import get_settings
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import ProjectRecord, ReleaseRecord

logger = logging.getLogger("cyberredteam.worker")


def _strategies(values: list[str] | None) -> list[StrategyType]:
    selected: list[StrategyType] = []
    for value in values or []:
        try:
            selected.append(StrategyType(value))
        except ValueError:
            continue
    return selected or [StrategyType.PROMPT_INJECTION]


def run_release_job(release_id: str) -> None:
    """Execute one persisted release from an RQ worker process."""
    settings = get_settings()
    store = SQLiteStore(settings.database_location)
    try:
        with store.SessionLocal() as session:
            release = session.get(ReleaseRecord, release_id)
            if release is None:
                raise ValueError(f"Release not found: {release_id}")
            project = session.get(ProjectRecord, release.project_id)
            if project is None:
                raise ValueError(f"Project not found for release: {release_id}")
            run_id = release.run_id
            if not run_id:
                raise ValueError(f"Release has no run id: {release_id}")
            # Materialise the small immutable target contract before closing
            # the session; the existing runner opens its own sessions while
            # persisting LangGraph evidence.
            project_data = {
                "project_id": project.project_id,
                "name": project.name,
                "slug": project.slug,
                "repository": project.repository,
                "environment": project.environment,
                "endpoint": project.endpoint,
                "request_template": project.request_template,
                "response_path": project.response_path,
                "strategies": list(project.strategies or []),
                "gate": dict(project.gate or {}),
            }
    finally:
        store.close()

    # Avoid importing FastAPI/API globals during worker discovery.
    from cyberredteam.api import run_release_orchestrator_thread

    project = ProjectRecord(**project_data)
    run_release_orchestrator_thread(
        release_id,
        run_id,
        project,
        _strategies(project_data["strategies"]),
        default_branch="main",
    )
    # The API runner persists failures instead of throwing from its thread
    # boundary. Re-raise here so RQ can apply its bounded retry policy.
    verify_store = SQLiteStore(settings.database_location)
    try:
        with verify_store.SessionLocal() as session:
            final_release = session.get(ReleaseRecord, release_id)
            if final_release is not None and final_release.status == "failed":
                raise RuntimeError(final_release.failure_code or "release evaluation failed")
    finally:
        verify_store.close()
    logger.info("Release %s worker job finished", release_id)


def main() -> None:
    """Start an RQ worker listening on the configured release queue."""
    from rq import Worker

    settings = get_settings()
    from cyberredteam.queue import get_connection

    worker = Worker([settings.release_queue_name], connection=get_connection())
    worker.work(with_scheduler=False)


if __name__ == "__main__":
    main()
