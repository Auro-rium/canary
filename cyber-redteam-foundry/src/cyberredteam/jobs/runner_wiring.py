"""Attach the real WP3 engine to the worker.

``make_runner(runtime, planner_factory=...)`` returns a ``CampaignRunner`` that
builds ``engine.EngineDeps`` per run and calls ``engine.run_campaign``:

* ``run_control``: the DB-backed ``runtime.control`` (cancel + kill switch);
* ``events``: an ``EventLogSink`` that also masks the target's own auth secrets
  (exact values) in every event before it is stored;
* ``limiter_factory``: the worker's :class:`SharedLimiters`, one token bucket
  per target shared by every campaign this process runs against it; its rate
  is only ever lowered, in place;
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

import asyncio
import importlib
import logging
import math
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any

from pydantic import SecretStr

from cyberredteam.contracts import CampaignPolicy, CampaignRequest, TargetConfig
from cyberredteam.engine import EngineDeps, EngineRepos, PlannerFactory, run_campaign
from cyberredteam.jobs.events import EventLogSink
from cyberredteam.jobs.execution import CampaignRunner
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo, CampaignRepo, ConversationRepo

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
    factory = getattr(importlib.import_module(module_name), attr)
    if not callable(factory):
        raise TypeError("planner_factory must name a callable")
    return factory


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
    """Token bucket (burst 1) for one target whose rate can only get stricter.

    Every campaign against the target holds this same object. There is exactly
    one bucket per target, ever: :meth:`set_rps` lowers the rate in place,
    keeping the token count, timestamp, lock and any Retry-After block, so a
    tightening never grants a free token and never splits the waiters.
    """

    def __init__(
        self,
        rps: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not math.isfinite(rps) or rps <= 0:
            raise ValueError("rps must be finite and > 0")
        self.rps = float(rps)
        self._clock = clock
        self._sleep = sleep
        self._tokens = 1.0
        self._stamp: float | None = None
        self._blocked_until = 0.0
        self._lock = asyncio.Lock()

    def set_rps(self, rps: float) -> None:
        """Lower the rate (a higher value is ignored).

        Synchronous with no ``await``, so it is atomic with respect to every
        coroutine on the event loop (``acquire`` re-reads the rate after each
        sleep). Tokens accrued since the last refill are settled at the *new*
        rate, so the change grants nothing the new rate would not have.
        """
        if not math.isfinite(rps) or rps <= 0 or rps >= self.rps:
            return
        if self._stamp is not None:
            now = self._clock()
            self._tokens = min(1.0, self._tokens + max(0.0, now - self._stamp) * rps)
            self._stamp = now
        self.rps = float(rps)

    async def penalize(self, target_id: str, seconds: float) -> None:
        self._blocked_until = max(self._blocked_until, self._clock() + max(0.0, seconds))

    async def acquire(self, target_id: str) -> None:
        async with self._lock:
            while True:
                now = self._clock()
                blocked = self._blocked_until - now
                if blocked > 0:
                    await self._sleep(blocked)
                    continue
                last = self._stamp if self._stamp is not None else now
                tokens = min(1.0, self._tokens + max(0.0, now - last) * self.rps)
                self._stamp = now
                if tokens >= 1.0 - 1e-9:
                    self._tokens = tokens - 1.0
                    return
                self._tokens = tokens
                await self._sleep((1.0 - tokens) / self.rps)


class SharedLimiters:
    """``engine.LimiterFactory``: one :class:`SharedTargetLimiter` per target id,
    shared by all campaigns this worker process runs (process-local)."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._by_target: dict[str, SharedTargetLimiter] = {}
        self._lock = threading.Lock()
        self._clock = clock
        self._sleep = sleep

    def __call__(self, target: TargetConfig, policy: CampaignPolicy) -> SharedTargetLimiter:
        rps = float(policy.rate_limit_rps)
        if not math.isfinite(rps) or rps <= 0:  # normalize_request already refuses these
            raise ValueError("rate_limit_rps must be finite and > 0")
        with self._lock:
            limiter = self._by_target.get(target.target_id)
            if limiter is None:
                limiter = SharedTargetLimiter(rps, clock=self._clock, sleep=self._sleep)
                self._by_target[target.target_id] = limiter
            else:
                limiter.set_rps(rps)
            return limiter


def webhook_notifier(
    url: str,
    *,
    url_check: Callable[[str], Any] | None = None,
    transport: Any = None,
) -> Callable[[Any], Awaitable[None]]:
    """``EngineDeps.on_call`` hook that POSTs the ``OnCallAlert`` (ids and hit
    names only, never evidence) to the target's on-call webhook (WP8 field).

    The URL is re-checked by the SSRF guard before every send, redirects are not
    followed, and the URL (a bearer secret for Slack/Discord) is never logged.
    """

    def _check(u: str) -> None:
        from cyberredteam.security.ownership import check_target_url

        check_target_url(u)

    check = url_check or _check

    async def notify(alert: Any) -> None:
        import httpx

        await asyncio.to_thread(check, url)
        # Straight to the transport: httpx.Client logs every request URL at INFO,
        # and a transport never follows redirects or reads proxy env vars.
        request = httpx.Request(
            "POST", url, json=alert.model_dump(mode="json"),
            extensions={"timeout": {"connect": 5.0, "read": 5.0, "write": 5.0, "pool": 5.0}},
        )
        tx = transport or httpx.AsyncHTTPTransport(retries=0)
        try:
            resp = await tx.handle_async_request(request)
            await resp.aread()
            await resp.aclose()
        finally:
            if transport is None:
                await tx.aclose()
        if resp.status_code >= 400:
            raise RuntimeError(f"on-call webhook returned HTTP {resp.status_code}")

    return notify


def _target_webhook_notifier(runtime: Any, target_id: str) -> Callable[[Any], Awaitable[None]] | None:
    targets = getattr(runtime, "targets", None)
    getter = getattr(targets, "get_oncall_webhook", None)
    if getter is None:
        return None
    try:
        url = getter(target_id)
    except Exception as exc:
        logger.warning("on-call webhook lookup failed (%s)", type(exc).__name__)
        return None
    return webhook_notifier(url) if url else None


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
        if "on_call" not in options:
            notifier = _target_webhook_notifier(runtime, request.target.target_id)
            if notifier is not None:
                options["on_call"] = notifier
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
