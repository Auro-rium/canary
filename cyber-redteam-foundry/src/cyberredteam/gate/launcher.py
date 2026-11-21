"""Candidate-campaign launcher: enqueue through the WP7 job queue and wait.

``--candidate`` mode compares two already-stored campaigns and needs no
launcher. Without it, :class:`QueueCampaignLauncher` creates a campaign for the
suite, enqueues it (``JobQueue.enqueue_campaign``), and polls the campaign row
until a worker has finished it or the timeout expires. A timed-out campaign is
cancelled so it does not run on unattended; if the cancel fails twice the campaign row is
marked ``failed`` (reason ``gate timeout``), never left running.

Suites are ScriptedPlanner packs (WP4): suite ``S`` is the set of techniques of
the packs under ``<packs_dir>/S/``; ``default`` is every pack in the directory.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from cyberredteam.contracts import CampaignPolicy, CampaignRequest

logger = logging.getLogger(__name__)


class LaunchError(Exception):
    """The candidate campaign could not be run to completion (the gate maps it to exit 2)."""


class CampaignLauncher(Protocol):
    def launch(self, target_id: str, suite: str) -> str:
        """Run ``suite`` against ``target_id`` to completion; return the campaign_id."""
        ...


def suite_techniques(suite: str, packs_dir: str | Path | None = None) -> list[str]:
    """Technique names of the pack suite (sorted, unique)."""
    from cyberredteam.planners.errors import PlannerConfigError
    from cyberredteam.planners.packs import PackLoader

    if suite != "default" and (not suite.replace("-", "").replace("_", "").isalnum()):
        raise LaunchError("invalid suite name")
    try:
        loader = PackLoader(packs_dir)
    except PlannerConfigError as exc:
        raise LaunchError(f"cannot load packs ({type(exc).__name__})") from None
    if suite == "default":
        packs = loader.packs()
    else:
        sub = loader.directory / suite
        if not sub.is_dir():
            raise LaunchError(f"unknown suite {suite!r}: no directory {sub.name}/ under the packs directory")
        packs = PackLoader(sub).packs()
    techniques = sorted({p.technique for p in packs})
    if not techniques:
        raise LaunchError(f"suite {suite!r} has no packs")
    return techniques


def _run_sync(coro_factory: Callable[[], Any]) -> Any:
    """Run a coroutine from sync code, in a worker thread if a loop is already running."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_factory())
    box: dict[str, Any] = {}

    def work() -> None:
        try:
            box["value"] = asyncio.run(coro_factory())
        except BaseException as exc:
            box["error"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


class QueueCampaignLauncher:
    """Creates a campaign for the suite, enqueues it via WP7 and waits for it."""

    def __init__(
        self,
        factory: Any,
        queue: Any,
        *,
        packs_dir: str | Path | None = None,
        trials_per_technique: int = 5,
        max_turns: int = 8,
        max_llm_cost_usd: float = 2.0,
        timeout_s: float = 1800.0,
        poll_interval_s: float = 2.0,
        created_by: str = "gate",
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        from cyberredteam.jobs.control import ControlStore
        from cyberredteam.storage.v2.repositories import CampaignRepo, SqlTargetStore

        self._queue = queue
        self._packs_dir = packs_dir
        self._trials = trials_per_technique
        self._max_turns = max_turns
        self._max_llm_cost_usd = max_llm_cost_usd
        self._timeout_s = timeout_s
        self._poll_s = poll_interval_s
        self._created_by = created_by
        self._sleep = sleep
        self._clock = clock
        self.campaigns = CampaignRepo(factory)
        self.targets = SqlTargetStore(factory)
        self.control = ControlStore(factory)
        self._factory = factory

    def _policy(self, target: Any, suite: str) -> CampaignPolicy:
        fields: dict[str, Any] = {
            "techniques": suite_techniques(suite, self._packs_dir),
            "trials_per_technique": self._trials,
            "max_turns": self._max_turns,
            "max_llm_cost_usd": self._max_llm_cost_usd,
        }
        if target.environment != "staging":  # production limits (plan section 4)
            fields.update(max_parallel_conversations=2, max_total_requests=300, rate_limit_rps=1.0)
        try:
            policy = CampaignPolicy(**fields)
            CampaignRequest(target=target, policy=policy)  # validates the production rules too
        except ValueError as exc:
            raise LaunchError(f"suite policy rejected ({type(exc).__name__})") from None
        return policy

    async def _enqueue(self, campaign_id: str) -> None:
        try:
            await self._queue.enqueue_campaign(campaign_id)
        finally:
            close = getattr(self._queue, "close", None)
            if close is not None:
                await close()

    def _cancel_with_retry(self, campaign_id: str) -> bool:
        for attempt in (1, 2):  # one retry
            try:
                self.control.request_cancel(campaign_id, "gate")
                return True
            except Exception as exc:
                logger.error(
                    "gate: could not cancel %s (attempt %d, %s)", campaign_id, attempt, type(exc).__name__
                )
        return False

    def _mark_timed_out(self, campaign_id: str) -> None:
        """Cancel failed twice: never leave the campaign running. The row goes to
        ``failed`` and a ``campaign_failed`` event records the reason ``gate timeout``."""
        try:  # best effort: stops a worker that is still running from flipping the status back
            self.control.request_cancel(campaign_id, "gate")
        except Exception as exc:
            logger.error("gate: could not set the cancel flag for %s (%s)", campaign_id, type(exc).__name__)
        try:
            # Compare-and-set: a campaign that just finished stays as it finished.
            if not self.campaigns.set_status_if_not_terminal(campaign_id, "failed"):
                logger.info("gate: %s already finished; timeout not recorded", campaign_id)
                return
        except Exception as exc:
            logger.error("gate: could not mark %s failed (%s)", campaign_id, type(exc).__name__)
            return
        try:
            from cyberredteam.contracts import CampaignFailedPayload
            from cyberredteam.jobs.events import EventLog

            EventLog(self._factory).append(
                campaign_id, "campaign_failed",
                CampaignFailedPayload(campaign_id=campaign_id, message="gate timeout"),
            )
        except Exception as exc:
            logger.error("gate: could not record the gate timeout for %s (%s)", campaign_id, type(exc).__name__)

    def launch(self, target_id: str, suite: str) -> str:
        from cyberredteam.storage.v2.repositories import TERMINAL_CAMPAIGN_STATUSES

        target = self.targets.get(target_id)
        if target is None:
            raise LaunchError("target not found")
        if target.verified is not True:
            raise LaunchError("target is not verified; refusing to launch")
        policy = self._policy(target, suite)
        campaign_id = f"gate-{uuid.uuid4().hex[:12]}"
        self.campaigns.create(campaign_id, target_id, policy, created_by=self._created_by)
        try:
            _run_sync(lambda: self._enqueue(campaign_id))
        except Exception as exc:
            self.campaigns.set_status(campaign_id, "failed")
            raise LaunchError(f"could not enqueue the candidate campaign ({type(exc).__name__})") from None
        logger.info("gate: campaign %s enqueued for suite %s", campaign_id, suite)

        deadline = self._clock() + self._timeout_s
        while True:
            rec = self.campaigns.get(campaign_id)
            if rec is not None and rec.status in TERMINAL_CAMPAIGN_STATUSES:
                if rec.status != "completed":
                    raise LaunchError(f"candidate campaign {campaign_id} ended {rec.status}")
                return campaign_id
            if self._clock() >= deadline:
                cancelled = self._cancel_with_retry(campaign_id)
                if not cancelled:
                    self._mark_timed_out(campaign_id)
                note = "cancel requested" if cancelled else "cancel failed; campaign marked failed"
                raise LaunchError(
                    f"candidate campaign {campaign_id} did not finish within {self._timeout_s:.0f}s ({note})"
                )
            self._sleep(self._poll_s)


__all__ = ["CampaignLauncher", "LaunchError", "QueueCampaignLauncher", "suite_techniques"]
