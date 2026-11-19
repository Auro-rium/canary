"""Attach the real WP3 engine to the worker.

``make_runner(runtime, planner_factory=...)`` returns a ``CampaignRunner`` that
builds ``engine.EngineDeps`` per run and calls ``engine.run_campaign``:

* ``run_control``: the DB-backed ``runtime.control`` (cancel + kill switch);
* ``events``: an ``EventLogSink`` that also masks the target's own auth secrets
  (exact values) in every event before it is stored;
* ``limiter_factory``: the worker's :class:`SharedLimiters`, one limiter per
  target shared by every campaign this process runs against it;
* ``adapter_factory``: left at the engine default (``default_adapter_factory``),
  which passes the engine's ``before_attempt`` hook (budget charge + RunControl
  re-check on every HTTP request, auth sub-requests included) and sets the
  ``X-Canary-Campaign`` header. Only tests override it via ``engine_options``.

The engine normalises the request itself (``normalize_request``) and raises
``CampaignRefused`` before writing anything for an unverified target or a
policy over the production limits; ``jobs/execution.py`` turns that into the
terminal ``refused`` outcome. The engine is resumable and idempotent per
campaign id, emits ``campaign_started`` and the terminal event itself, and sets
the terminal status; ``jobs/execution.py`` only fills in what it did not.

The planner factory is injected (WP4 provides real planners). With none
configured the runner fails closed: ``NoPlannerConfigured("no planner configured")``.
"""

from __future__ import annotations

import importlib
import logging
import math
import threading
from typing import Any

from pydantic import SecretStr

from cyberredteam.contracts import CampaignPolicy, CampaignRequest, TargetConfig
from cyberredteam.engine import EngineDeps, EngineRepos, PlannerFactory, run_campaign
from cyberredteam.jobs.events import EventLogSink
from cyberredteam.jobs.execution import CampaignRunner
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo, CampaignRepo, ConversationRepo
from cyberredteam.transport.rate_limit import InProcessTokenBucket

logger = logging.getLogger(__name__)


class NoPlannerConfigured(RuntimeError):
    """No planner factory is configured for this worker."""


def load_planner_factory(spec: str | None) -> PlannerFactory | None:
    """Resolve ``"package.module:callable"`` to a planner factory (``None`` if unset)."""
    if not spec:
        return None
    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise ValueError("planner_factory must look like 'package.module:callable'")
    return getattr(importlib.import_module(module_name), attr)


def auth_secret_values(target: TargetConfig) -> tuple[str, ...]:
    """The revealed values of every ``SecretStr`` field of the target's auth."""
    out: list[str] = []
    for _, value in getattr(target, "auth", None) or ():
        if isinstance(value, SecretStr):
            secret = value.get_secret_value()
            if secret:
                out.append(secret)
    return tuple(out)


class SharedTargetLimiter:
    """A per-target limiter whose rate can only ever get stricter.

    Every campaign against the target holds this same object; when a campaign
    with a lower ``rate_limit_rps`` arrives, the underlying bucket is replaced
    by a stricter one for all holders. A higher rps never loosens it.
    """

    def __init__(self, rps: float) -> None:
        self.rps = rps
        self._bucket = InProcessTokenBucket(rps)

    def tighten(self, rps: float) -> None:
        if rps < self.rps:
            self.rps = rps
            self._bucket = InProcessTokenBucket(rps)

    async def acquire(self, target_id: str) -> None:
        await self._bucket.acquire(target_id)

    async def penalize(self, target_id: str, seconds: float) -> None:
        await self._bucket.penalize(target_id, seconds)


class SharedLimiters:
    """``engine.LimiterFactory``: one :class:`SharedTargetLimiter` per target id,
    shared by all campaigns this worker process runs (process-local)."""

    def __init__(self) -> None:
        self._by_target: dict[str, SharedTargetLimiter] = {}
        self._lock = threading.Lock()

    def __call__(self, target: TargetConfig, policy: CampaignPolicy) -> SharedTargetLimiter:
        rps = float(policy.rate_limit_rps)
        if not math.isfinite(rps) or rps <= 0:  # normalize_request already refuses these
            raise ValueError("rate_limit_rps must be finite and > 0")
        with self._lock:
            limiter = self._by_target.get(target.target_id)
            if limiter is None:
                limiter = self._by_target[target.target_id] = SharedTargetLimiter(rps)
            else:
                limiter.tighten(rps)
            return limiter


def make_runner(
    runtime: Any,
    planner_factory: PlannerFactory | None = None,
    engine_options: dict[str, Any] | None = None,
    limiters: SharedLimiters | None = None,
) -> CampaignRunner:
    shared = limiters if limiters is not None else SharedLimiters()

    async def runner(request: CampaignRequest, campaign_id: str) -> Any:
        if planner_factory is None:
            logger.error("no planner configured: set PLANNER_FACTORY=package.module:callable")
            raise NoPlannerConfigured("no planner configured")
        options = {"limiter_factory": shared, **(engine_options or {})}
        deps = EngineDeps(
            repos=EngineRepos(
                conversations=ConversationRepo(runtime.factory),
                campaigns=CampaignRepo(runtime.factory),
                budget=BudgetLedgerRepo(runtime.factory),
            ),
            planner_factory=planner_factory,
            run_control=runtime.control,
            events=EventLogSink(runtime.events, auth_secret_values(request.target)),
            **options,
        )
        return await run_campaign(request, campaign_id, deps)

    return runner
