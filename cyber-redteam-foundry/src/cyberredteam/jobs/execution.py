"""Campaign execution inside a worker: load the request, run, heartbeat, finalize.

Independent of the queue backend; procrastinate (``jobs/queue.py``) only calls
:func:`execute_campaign`. The real WP3 runner is injected as a
:data:`CampaignRunner`; until it is wired (see ``jobs/runner_wiring.py``) the
worker fails closed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.contracts import CampaignRequest
from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.events import EventLog
from cyberredteam.jobs.resume import HeartbeatRepo
from cyberredteam.storage.v2.repositories import (
    TERMINAL_CAMPAIGN_STATUSES,
    AuditRepo,
    CampaignRepo,
    SqlTargetStore,
)

logger = logging.getLogger(__name__)

# ``async (request, campaign_id) -> Any``. WP3's ``run_campaign(request,
# campaign_id, deps)`` is adapted to this shape in ``runner_wiring.py``.
CampaignRunner = Callable[[CampaignRequest, str], Awaitable[Any]]


@dataclass
class JobRuntime:
    factory: sessionmaker[Session]
    runner: CampaignRunner
    control: DbRunControl
    heartbeat_interval_s: float = 10.0
    stale_after_s: float = 45.0
    worker_id: str = field(default_factory=lambda: f"worker-{uuid.uuid4().hex[:8]}")

    def __post_init__(self) -> None:
        self.campaigns = CampaignRepo(self.factory)
        self.targets = SqlTargetStore(self.factory)
        self.events = EventLog(self.factory)
        self.audit = AuditRepo(self.factory)
        self.heartbeats = HeartbeatRepo(self.factory)


class CampaignLoadError(Exception):
    """The stored campaign cannot be turned into a runnable request."""


def load_request(runtime: JobRuntime, campaign_id: str) -> CampaignRequest:
    """Rebuild the ``CampaignRequest`` from the stored campaign + target.

    Goes through ``CampaignRequest`` validation again, so production policy
    rules are enforced at run time as well as at creation. Unverified targets
    are refused (defence in depth behind the API gate).
    """
    rec = runtime.campaigns.get(campaign_id)
    if rec is None:
        raise CampaignLoadError("campaign not found")
    target = runtime.targets.get(rec.target_id)
    if target is None:
        raise CampaignLoadError("target not found")
    if not target.verified:
        raise CampaignLoadError("target is not verified")
    return CampaignRequest(target=target, policy=rec.policy)


async def _heartbeat_loop(runtime: JobRuntime, campaign_id: str) -> None:
    while True:
        await asyncio.sleep(runtime.heartbeat_interval_s)
        try:
            await asyncio.to_thread(runtime.heartbeats.beat, campaign_id, runtime.worker_id)
        except Exception as exc:  # a missed beat only risks an early (idempotent) resume
            logger.warning("heartbeat failed for %s (%s)", campaign_id, type(exc).__name__)


async def _to_thread(fn: Callable[..., Any], *args: Any) -> Any:
    return await asyncio.to_thread(fn, *args)


async def _finish(runtime: JobRuntime, campaign_id: str, signal: str | None, error: str | None) -> str:
    """Set the terminal status (unless the runner already did) and emit the event."""
    rec = await _to_thread(runtime.campaigns.get, campaign_id)
    if rec is not None and rec.status in TERMINAL_CAMPAIGN_STATUSES:
        outcome = rec.status
    else:
        if error is not None:
            outcome = "failed"
        elif signal == "killed":
            outcome = "failed"  # needs an explicit restart; never auto-resumed
        elif signal == "cancelled":
            outcome = "cancelled"
        else:
            outcome = "completed"
        await _to_thread(runtime.campaigns.set_status, campaign_id, outcome)
    event = {
        "completed": "campaign_completed",
        "cancelled": "campaign_cancelled",
        "failed": "campaign_killed" if signal == "killed" else "campaign_failed",
    }[outcome]
    payload: dict[str, Any] = {"status": outcome}
    if error:
        payload["error"] = error
    await _to_thread(runtime.events.append, campaign_id, event, payload)
    if signal == "killed":
        await _to_thread(
            runtime.audit.record, runtime.worker_id, "campaign.killed", f"campaign:{campaign_id}", {}
        )
    return outcome


async def execute_campaign(runtime: JobRuntime, campaign_id: str) -> str:
    """Run (or resume) one campaign. Returns a short outcome string.

    ``skipped`` (unknown/terminal campaign, or another live worker holds it),
    otherwise the final campaign status.
    """
    rec = await _to_thread(runtime.campaigns.get, campaign_id)
    if rec is None:
        logger.error("campaign %s not found; dropping job", campaign_id)
        return "skipped"
    if rec.status in TERMINAL_CAMPAIGN_STATUSES:
        return "skipped"

    runtime.control.invalidate()
    signal = await runtime.control.check(campaign_id)
    if signal is not None:  # stopped before it started (or already running)
        return await _finish(runtime, campaign_id, signal, None)

    if not await _to_thread(
        runtime.heartbeats.claim, campaign_id, runtime.worker_id, runtime.stale_after_s
    ):
        logger.info("campaign %s is held by another live worker; skipping", campaign_id)
        return "skipped"

    resumed = rec.status == "running"
    try:
        request = await _to_thread(load_request, runtime, campaign_id)
    except Exception as exc:
        logger.error("cannot load campaign %s: %s", campaign_id, exc)
        await _to_thread(runtime.heartbeats.release, campaign_id)
        return await _finish(runtime, campaign_id, None, f"load_failed: {exc}")

    await _to_thread(runtime.campaigns.set_status, campaign_id, "running")
    await _to_thread(
        runtime.events.append, campaign_id,
        "campaign_resumed" if resumed else "campaign_started", {"worker": runtime.worker_id},
    )
    beat = asyncio.create_task(_heartbeat_loop(runtime, campaign_id))
    error: str | None = None
    try:
        await runtime.runner(request, campaign_id)
    except asyncio.CancelledError:
        # Worker shutting down: leave status "running" and drop the heartbeat so
        # the reaper resumes the campaign from its persisted turns.
        await asyncio.shield(_to_thread(runtime.heartbeats.release, campaign_id))
        raise
    except Exception as exc:
        error = type(exc).__name__  # never echo exception text (may hold evidence)
        logger.error("campaign %s failed: %s", campaign_id, error)
    finally:
        beat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await beat

    runtime.control.invalidate()
    signal = await runtime.control.check(campaign_id)
    outcome = await _finish(runtime, campaign_id, signal, error)
    await _to_thread(runtime.heartbeats.release, campaign_id)
    return outcome
