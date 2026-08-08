"""Redis/RQ adapter for durable release jobs.

The API only enqueues after the release row has been committed. RQ's stable
job id makes retries and duplicate delivery idempotent at the release
executor boundary. Redis/RQ are imported lazily so local SQLite users do not
need a running Redis server merely to import the FastAPI application.
"""

from __future__ import annotations

from typing import Any

from canary.release_execution import deterministic_job_id
from cyberredteam.settings import get_settings


def _redis_url() -> str:
    url = get_settings().redis_url
    if not url:
        raise RuntimeError("REDIS_URL must be configured for RQ release execution")
    return url


def get_connection() -> Any:
    """Return a Redis connection configured from ``REDIS_URL``."""
    from redis import Redis

    return Redis.from_url(_redis_url(), decode_responses=False)


def get_queue() -> Any:
    """Return the configured RQ release queue."""
    from rq import Queue

    settings = get_settings()
    return Queue(
        name=settings.release_queue_name,
        connection=get_connection(),
        default_timeout=settings.release_job_timeout_seconds,
    )


def enqueue_release(release_id: str) -> str:
    """Enqueue a release once and return its deterministic RQ job id."""
    if not release_id.strip():
        raise ValueError("release_id must not be blank")
    job_id = deterministic_job_id(release_id)
    queue = get_queue()
    existing = queue.fetch_job(job_id)
    if existing is not None and existing.get_status(refresh=False) in {"queued", "started", "deferred", "scheduled"}:
        return job_id

    from rq import Retry

    queue.enqueue(
        "cyberredteam.worker.run_release_job",
        release_id,
        job_id=job_id,
        job_timeout=get_settings().release_job_timeout_seconds,
        retry=Retry(max=get_settings().max_retries, interval=[30, 120, 300]),
        result_ttl=86400,
        failure_ttl=604800,
    )
    return job_id
