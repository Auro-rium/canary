"""Target adapters for the legacy v1 attack flow.

The v1 graph (``attacker_branch``) is synchronous and sends one self-contained
prompt per attack. ``SessionTargetAdapter`` serves it through the v2
``SessionAdapter`` (one fresh adapter per attack), so the legacy flow gets the
same transport and guards as v2 (registered verified target only, SSRF guard,
kill switch, rate limit): auth handling, response caps, ``X-Canary-Campaign``
header, no redirects, retry rules. The old ``requests``-based
``HttpTargetAdapter`` has been deleted.
"""

from __future__ import annotations

import asyncio
import math
import threading
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, Dict, Optional, Tuple

from pydantic import HttpUrl, TypeAdapter
from sqlalchemy.exc import SQLAlchemyError

from cyberredteam.contracts import (
    RESERVED_HEADERS,
    BearerAuth,
    HeaderAuth,
    NoAuth,
    TargetConfig,
    validate_request_template,
)
from cyberredteam.jobs.control import ControlStore, env_kill_switch_active
from cyberredteam.logging import log_event, setup_logging
from cyberredteam.security.ownership import TargetRefused, check_target_urls
from cyberredteam.storage.v2.repositories import SqlTargetStore
from cyberredteam.transport.rate_limit import RateLimiter
from cyberredteam.transport.session_adapter import SendAborted, SessionAdapter, TurnResult

logger = setup_logging()

_LEGACY_PLACEHOLDER = "{{PROMPT}}"
PRODUCTION_MAX_RPS = 1.0
_URL = TypeAdapter(HttpUrl)


class TargetAdapter:
    """Abstract adapter for different target types."""

    def execute_attack(self, payload: str, label: str = "") -> Tuple[str, Optional[str]]:
        """Send an adversarial payload to the target.

        Args:
            payload: The exact prompt/input to send to the target agent.
            label: Optional technique/category label, used only for logging.

        Returns:
            Tuple of (response_text, canary_token).
            canary_token is non-None when the adapter injected a canary into the
            target's context; the evaluator checks if it was exfiltrated.
        """
        raise NotImplementedError

    def reset_context(self) -> None:
        """Reset target context if supported."""
        pass


def _run_sync(coro_factory) -> Any:
    """Run a coroutine to completion from sync code, even inside a running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_factory())
    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            box["value"] = asyncio.run(coro_factory())
        except BaseException as exc:  # re-raised in the caller
            box["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


class V1TargetRefused(TargetRefused):
    """The v1 flow refuses to contact this target (not registered, not verified,
    archived, or outside the ALLOWED_TARGETS narrowing)."""


class SpacingLimiter:
    """Thread-safe, loop-agnostic rate limiter (``RateLimiter`` protocol).

    Reserves send slots ``1/rps`` apart under a ``threading.Lock``, so it works
    across the fresh event loops of the sync v1 flow and across threads. The
    first send is immediate; ``penalize`` pushes the next slot out.
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
        self._interval = 1.0 / float(rps)
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_free: dict[str, float] = {}

    async def acquire(self, target_id: str) -> None:
        with self._lock:
            now = self._clock()
            slot = max(now, self._next_free.get(target_id, now))
            self._next_free[target_id] = slot + self._interval
        if slot > now:
            await self._sleep(slot - now)

    async def penalize(self, target_id: str, seconds: float) -> None:
        with self._lock:
            until = self._clock() + max(0.0, seconds)
            self._next_free[target_id] = max(self._next_free.get(target_id, 0.0), until)


_SHARED_LIMITERS: dict[str, SpacingLimiter] = {}
_SHARED_LOCK = threading.Lock()


def shared_limiter(endpoint: str, rps: float = 1.0) -> SpacingLimiter:
    """Process-wide limiter for one endpoint, so per-attack adapters (the v1 graph
    builds one per branch) still share a single budget."""
    key = endpoint.rstrip("/")
    with _SHARED_LOCK:
        limiter = _SHARED_LIMITERS.get(key)
        if limiter is None:
            limiter = _SHARED_LIMITERS[key] = SpacingLimiter(rps)
        return limiter


def default_target_store() -> SqlTargetStore:
    """The v2 target registry on the configured database."""
    from cyberredteam.auth.deps import get_db_factory

    return SqlTargetStore(get_db_factory())


def _normalise(url: str) -> str:
    try:
        return str(_URL.validate_python(url)).rstrip("/")
    except ValueError:
        return url.rstrip("/")


def resolve_registered_target(endpoint_or_id: str, store: SqlTargetStore) -> TargetConfig:
    """Return the registered, ownership-verified target for an id or exact endpoint.

    Raises :class:`V1TargetRefused` for an unknown, unverified or archived target,
    or when ``ALLOWED_TARGETS`` is set and does not list it. ``ALLOWED_TARGETS``
    only narrows; it never admits an unregistered target.
    """
    wanted = endpoint_or_id.strip()
    try:
        try:
            uuid.UUID(wanted)
            found = store.get(wanted)
            candidates = [found] if found else []
        except ValueError:
            norm = _normalise(wanted)
            candidates = [t for t in store.list() if _normalise(str(t.endpoint)) == norm]
        candidates = [
            t for t in candidates
            if (m := store.meta(t.target_id)) is not None and not m.archived
        ]
    except SQLAlchemyError:
        raise V1TargetRefused("refusing to send: the target registry is unavailable.") from None
    if not candidates:
        raise V1TargetRefused(
            "refusing to send: the target is not a registered target. Register it "
            "(POST /api/v2/targets) and verify ownership first."
        )
    target = next((t for t in candidates if t.verified is True), None)
    if target is None:
        raise V1TargetRefused(
            "refusing to send: the target is registered but ownership is not verified."
        )
    from cyberredteam.settings import get_settings

    allowed = [a.strip() for a in get_settings().allowed_targets.split(",") if a.strip()]
    if allowed and not any(
        a == target.target_id or _normalise(a) == _normalise(str(target.endpoint)) for a in allowed
    ):
        raise V1TargetRefused("refusing to send: the target is not in ALLOWED_TARGETS.")
    return target


def _default_kill_check(factory: Any) -> bool:
    """True when the env kill switch or the DB control flag is set; fails closed."""
    try:
        return bool(env_kill_switch_active() or ControlStore(factory).kill_switch_state()[0])
    except Exception:  # noqa: BLE001 - cannot read the flag: do not send
        return True


class SessionTargetAdapter(TargetAdapter):
    """Sync ``TargetAdapter`` over a fresh v2 ``SessionAdapter`` per attack.

    Enforced, in the same way as the v2 engine:

    * Construction refuses (:class:`V1TargetRefused`) unless ``endpoint`` (an exact
      endpoint URL or a target id) names a target that exists in the target
      registry (``SqlTargetStore``) and was ownership-verified. ``verified`` is
      read from the store, never set here. ``ALLOWED_TARGETS``, if set, only
      narrows this. The registered auth, template and response path win;
      legacy arguments only fill what the registered target leaves unset.
    * Before every HTTP request (each attempt, retry and auth sub-request) the
      SSRF guard ``check_target_urls`` runs on the endpoint and auth URLs:
      private, loopback, link-local and metadata hosts are refused and nothing
      is sent. ``ownership_options`` is the same dependency-injection seam as
      v2's ``get_ownership_options`` (tests only; production passes nothing).
    * Before every request the kill switch (``CANARY_KILL_SWITCH`` or the DB
      control flag) is checked; when set nothing is sent.
    * One rate limiter per adapter (``share_limiter=True``: one per endpoint for the
      whole process, which the per-attack callers use), honouring
      ``rate_limit_rps`` and capped at 1 rps for production targets.
    * ``X-Canary-Campaign`` is added by the v2 ``SessionAdapter``.

    Not enforced here: campaign budget (the v1 flow has no budget ledger) and
    org scoping.

    Legacy arguments: ``api_key`` -> bearer auth and an ``Authorization: Bearer x``
    header -> bearer auth (only when the registered target has no auth); the
    first other custom header -> header auth; further headers are plain client
    headers; ``{{PROMPT}}`` in the request template -> ``{{MESSAGE}}``.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: Optional[str] = None,
        timeout: int = 60,
        headers: Optional[Dict[str, str]] = None,
        request_template: Optional[str] = None,
        response_path: Optional[str] = None,
        *,
        store: Optional[SqlTargetStore] = None,
        campaign_id: str = "legacy-v1",
        transport: Any = None,
        rate_limit_rps: float = 1.0,
        rate_limiter: Optional[RateLimiter] = None,
        share_limiter: bool = False,
        ownership_options: Optional[Dict[str, Any]] = None,
        kill_check: Optional[Callable[[], bool]] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        store = store if store is not None else default_target_store()
        registered = resolve_registered_target(endpoint, store)
        self.endpoint = str(registered.endpoint).rstrip("/")
        self.target_id = self.endpoint  # For logging
        self.campaign_id = campaign_id
        self._transport = transport
        self._store = store
        self._allowed_hosts = store.get_allowed_auth_hosts(registered.target_id)
        self._url_options = dict(ownership_options or {})
        self._kill_check = kill_check or (lambda: _default_kill_check(store.factory))
        self._extra_headers: dict[str, str] = {}
        auth: Any = registered.auth
        take_legacy_auth = isinstance(auth, NoAuth)
        if take_legacy_auth and api_key:
            auth = BearerAuth(token=api_key)
        for name, value in (headers or {}).items():
            lowered = name.lower()
            if lowered in RESERVED_HEADERS:
                continue
            if lowered == "authorization":
                if take_legacy_auth and value.lower().startswith("bearer "):
                    auth = BearerAuth(token=value[7:].strip())
                continue
            if take_legacy_auth and isinstance(auth, NoAuth):
                auth = HeaderAuth(header_name=name, value=value)
            else:
                self._extra_headers[name] = value
        template = registered.request_template
        if template is None and request_template:
            template = validate_request_template(request_template.replace(_LEGACY_PLACEHOLDER, "{{MESSAGE}}"))
        self._config = registered.model_copy(
            update={
                "auth": auth,
                "request_template": template,
                "response_path": registered.response_path or response_path,
            }
        )
        rps = float(rate_limit_rps)
        if registered.environment == "production":
            rps = min(rps, PRODUCTION_MAX_RPS)
        if rate_limiter is None:
            rate_limiter = (
                shared_limiter(self.endpoint, rps) if share_limiter
                else SpacingLimiter(rps, clock=clock, sleep=sleep)
            )
        self._limiter: RateLimiter = rate_limiter
        self.last_observation: Dict[str, Any] = {
            "stage": "target_request",
            "status": "not_started",
            "endpoint": self.endpoint,
        }
        logger.info(f"SessionTargetAdapter initialized → {self.endpoint}")

    async def _before_attempt(self) -> None:
        if await asyncio.to_thread(self._kill_check):
            raise SendAborted("kill switch active")
        try:
            await asyncio.to_thread(
                lambda: check_target_urls(
                    self.endpoint, self._config.auth, self._allowed_hosts, **self._url_options
                )
            )
        except TargetRefused as exc:
            raise SendAborted(f"target refused: {exc}") from None

    async def _send(self, payload: str) -> TurnResult:
        adapter = SessionAdapter(
            self._config,
            campaign_id=self.campaign_id,
            rate_limiter=self._limiter,
            transport=self._transport,
            before_attempt=self._before_attempt,
        )
        try:
            adapter._client.headers.update(self._extra_headers)
            return await adapter.send(payload)
        finally:
            await adapter.aclose()

    def execute_attack(self, payload: str, label: str = "") -> Tuple[str, Optional[str]]:
        logger.info(f"target '{self.endpoint}' executing attack type '{label}'")
        try:
            result: TurnResult = _run_sync(lambda: self._send(payload))
        except Exception as exc:
            self.last_observation = {
                "stage": "target_request", "status": "error", "endpoint": self.endpoint,
                "error_type": type(exc).__name__,
            }
            log_event(logger, "target_error", **self.last_observation)
            return f"(target error: {type(exc).__name__})", None
        obs: Dict[str, Any] = {
            "stage": "target_request",
            "status": "response" if result.error is None else result.error.kind.value,
            "endpoint": self.endpoint,
            "http_status": result.http_status,
            "latency_ms": round(result.latency_ms, 2),
            "request_hash": result.request_hash,
            "response_hash": result.response_hash,
            "response_bytes": result.response_bytes,
        }
        if result.error is not None:
            obs["error_type"] = result.error.kind.value
        self.last_observation = obs
        log_event(logger, "target_response" if result.error is None else "target_error", **obs)
        if result.error is not None:
            return f"(target error: {result.error})", None
        return result.response_text, None


__all__ = [
    "SessionTargetAdapter",
    "SpacingLimiter",
    "TargetAdapter",
    "V1TargetRefused",
    "resolve_registered_target",
    "shared_limiter",
]
