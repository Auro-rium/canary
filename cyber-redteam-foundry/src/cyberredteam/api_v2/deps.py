"""Shared dependencies for the /api/v2 routers (WP8)."""

from __future__ import annotations

from typing import Any

from fastapi import Depends
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.auth.deps import get_db_factory
from cyberredteam.jobs.queue import JobQueue, get_default_queue
from cyberredteam.storage.v2.repositories import SqlTargetStore


def get_target_store(factory: sessionmaker[Session] = Depends(get_db_factory)) -> SqlTargetStore:
    return SqlTargetStore(factory)


def get_ownership_options() -> dict[str, Any]:
    """Keyword options for ``verify_ownership`` / ``check_target_urls``.

    Private/loopback targets stay refused; tests override this dependency to
    inject fake transports and resolvers.
    """
    return {"allow_private_targets": False}


def get_job_queue() -> JobQueue:
    return get_default_queue()


URL_CHECK_OPTIONS = ("allow_private_targets", "resolve_host")


def url_check_options(ownership_options: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in ownership_options.items() if k in URL_CHECK_OPTIONS}
