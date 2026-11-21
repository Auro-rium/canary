"""SessionAdapter: a stateful, rate-limited HTTP client for one target conversation.

One instance is one conversation session. It never returns an error as reply
text: failures come back as a typed :class:`TargetError` on the
:class:`TurnResult`.

Retry policy: network errors that mean the request was not delivered
(connect/write/read/protocol errors) and 5xx are retried at most twice with
backoff; 429 and 503-with-Retry-After wait the advertised time and retry (max
twice); a 401 triggers one re-authentication. A read *timeout* is not retried
(the target may have processed the message), a 2xx is never retried and other
4xx are never retried.

Every outgoing HTTP request (each attempt, each retry, and each auth
sub-request: OAuth token fetch, cookie login, 401 re-auth) first passes
:meth:`SessionAdapter._gate`: cancel check, the optional ``before_attempt``
hook (the engine charges the budget and checks cancel/kill there; it raises
:class:`SendAborted` to refuse), then the rate limiter. ``cancel()`` also
interrupts a pending backoff or Retry-After wait.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Any

import httpx

from cyberredteam.contracts import TargetConfig, ToolCallObservation
from cyberredteam.observability.hooks import trace_op
from cyberredteam.transport.auth import AuthFailure, build_auth
from cyberredteam.transport.rate_limit import RateLimiter
from cyberredteam.transport.streaming import (
    StreamParseError,
    assemble_text,
    get_path,
    parse_stream,
)

CAMPAIGN_HEADER = "X-Canary-Campaign"
FALLBACK_KEYS = ("response", "output", "content", "text")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RETRIES = 2
MAX_RATE_LIMIT_WAITS = 2
BACKOFF_BASE_S = 0.5

# Only failures that prove no status line arrived. ReadError / RemoteProtocolError
# are NOT here: they may follow a delivered request, and a message must never be
# re-sent once the target might have processed it.
_RETRYABLE_BEFORE_RESPONSE = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
    httpx.WriteError,
)


class _TooLarge(Exception):
    pass


class SendAborted(Exception):
    """Raised by a ``before_attempt`` hook to refuse the next HTTP request
    (e.g. budget exhausted, campaign cancelled or killed). The send returns a
    ``cancelled`` TargetError and nothing further is sent."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason

_TOOL_HEURISTICS = (
    re.compile(
        r"(?:call(?:ing)?|invoke[sd]?|using?|ran?)\s+([a-z_]+(?:_tool|_lookup|_search|_executor))",
        re.IGNORECASE,
    ),
    re.compile(r"\b([a-z_]+)\s*\(\s*(?:['\"]?\w+['\"]?\s*(?:,\s*['\"]?\w+['\"]?)*)\s*\)", re.IGNORECASE),
)


class TargetErrorKind(str, Enum):
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    HTTP_4XX = "http_4xx"
    HTTP_5XX = "http_5xx"
    BAD_JSON = "bad_json"
    EXTRACT_FAILED = "extract_failed"
    RATE_LIMITED = "rate_limited"
    HTTP_REDIRECT = "http_redirect"
    RESPONSE_TOO_LARGE = "response_too_large"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class TargetError:
    kind: TargetErrorKind
    message: str = ""

    def __str__(self) -> str:
        return f"{self.kind.value}: {self.message}" if self.message else self.kind.value


@dataclass
class TurnResult:
    response_text: str = ""
    tool_calls: list[ToolCallObservation] = field(default_factory=list)
    http_status: int | None = None
    latency_ms: float = 0.0
    request_hash: str = ""
    response_hash: str = ""
    response_bytes: int = 0
    error: TargetError | None = None
    attempts: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None


def _sha16(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def parse_retry_after(value: str | None) -> float | None:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP-date)."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def render_template(node: Any, values: dict[str, Any]) -> Any:
    """Structurally substitute placeholder string values in a parsed template."""
    if isinstance(node, dict):
        return {k: render_template(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [render_template(v, values) for v in node]
    if isinstance(node, str) and node in values:
        return values[node]
    return node


def _heuristic_tool_calls(text: str) -> list[ToolCallObservation]:
    seen: list[str] = []
    for pat in _TOOL_HEURISTICS:
        for m in pat.finditer(text):
            name = m.group(1)
            if name not in seen:
                seen.append(name)
    return [ToolCallObservation(name=n, source="heuristic") for n in seen]


def _structured_tool_calls(items: Any) -> list[ToolCallObservation]:
    if not isinstance(items, list):
        return []
    out: list[ToolCallObservation] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        fn = item.get("function") if isinstance(item.get("function"), dict) else {}
        name = item.get("name") or fn.get("name")
        if not isinstance(name, str) or not name:
            continue
        args: Any = item.get("arguments", fn.get("arguments", item.get("args", {})))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except ValueError:
                args = {"_raw": args}
        if not isinstance(args, dict):
            args = {"value": args}
        call_id = item.get("call_id") or item.get("id")
        out.append(
            ToolCallObservation(
                name=name,
                arguments=args,
                call_id=str(call_id) if call_id is not None else None,
                source="structured",
            )
        )
    return out


class SessionAdapter:
    """One conversation against one target. Use ``async with`` or call ``aclose()``."""

    def __init__(
        self,
        config: TargetConfig,
        *,
        campaign_id: str,
        rate_limiter: RateLimiter,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        before_attempt: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        self._config = config
        self._before_attempt = before_attempt
        self._cancel_event = asyncio.Event()
        self._campaign_id = campaign_id
        self._limiter = rate_limiter
        self._sleep = sleep
        self._auth = build_auth(config.auth, clock, gate=self._gate)
        self._template: Any = json.loads(config.request_template) if config.request_template else None
        self._history: list[dict[str, str]] = []
        self._session_id: str | None = None
        self._cancelled = False
        self._send_lock = asyncio.Lock()
        self._deadline_s = float(config.timeout_s)
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=float(config.timeout_s),
            headers={CAMPAIGN_HEADER: campaign_id},
            follow_redirects=False,
        )

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def __aenter__(self) -> SessionAdapter:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def cancel(self) -> None:
        """Cooperative cancel: the next send (or retry) returns ``cancelled`` unsent,
        and a pending backoff / Retry-After wait ends at once."""
        self._cancelled = True
        self._cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    async def _gate(self) -> None:
        """Run before every outgoing HTTP request, including auth sub-requests."""
        if self._cancelled:
            raise SendAborted("cancelled")
        if self._before_attempt is not None:
            await self._before_attempt()
        await self._limiter.acquire(self._config.target_id)
        if self._cancelled:
            raise SendAborted("cancelled")

    async def _wait(self, seconds: float) -> None:
        """Sleep, unless cancel() is called first."""
        if self._cancelled:
            return
        sleeper = asyncio.ensure_future(self._sleep(seconds))
        waiter = asyncio.ensure_future(self._cancel_event.wait())
        try:
            await asyncio.wait({sleeper, waiter}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (sleeper, waiter):
                if not task.done():
                    task.cancel()

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def history(self) -> list[dict[str, str]]:
        return list(self._history)

    def restore(self, history: list[dict[str, str]], session_id: str | None = None) -> None:
        """Seed a fresh adapter with a persisted conversation (engine resume).

        ``history`` is the OpenAI-style transcript of earlier successful turns
        (used for ``{{HISTORY}}``); ``session_id`` is the captured server
        session id. Cookie jars cannot be restored. Only valid before the
        first send.
        """
        if self._history or self._session_id is not None:
            raise RuntimeError("restore() is only valid on a fresh adapter")
        for item in history:
            if item.get("role") not in ("user", "assistant") or not isinstance(item.get("content"), str):
                raise ValueError("history items must be {role: user|assistant, content: str}")
        self._history = [{"role": h["role"], "content": h["content"]} for h in history]
        self._session_id = session_id or None

    # ── Request building ─────────────────────────────────────────────────────

    def _build_body(self, message: str) -> Any:
        if self._template is None:
            return {"message": message}
        values: dict[str, Any] = {
            "{{MESSAGE}}": message,
            "{{SESSION_ID}}": self._session_id,
            "{{HISTORY}}": [*self._history, {"role": "user", "content": message}],
        }
        return render_template(self._template, values)

    # ── Send ─────────────────────────────────────────────────────────────────

    @trace_op("target.send")
    async def send(self, message: str) -> TurnResult:
        async with self._send_lock:
            return await self._send_locked(message)

    async def _send_locked(self, message: str) -> TurnResult:
        started = time.perf_counter()
        result = TurnResult()
        body = json.dumps(self._build_body(message), separators=(",", ":")).encode()
        result.request_hash = _sha16(body)
        try:
            await self._send_with_retries(body, result)
        except SendAborted as exc:
            result.error = TargetError(TargetErrorKind.CANCELLED, f"aborted before send ({exc.reason})")
        finally:
            result.latency_ms = (time.perf_counter() - started) * 1000.0
        if result.error is None:
            self._history.append({"role": "user", "content": message})
            self._history.append({"role": "assistant", "content": result.response_text})
        return result

    async def _send_with_retries(self, body: bytes, result: TurnResult) -> None:
        net_retries = 0
        rate_waits = 0
        reauthed = False
        while True:
            if self._cancelled:
                result.error = TargetError(TargetErrorKind.CANCELLED, "cancelled before send")
                return
            await self._gate()

            result.attempts += 1
            got_response = False
            try:
                headers = {"Content-Type": "application/json", "Accept": "*/*"}
                headers.update(await self._auth.headers(self._client))
                request = self._client.build_request(
                    "POST", str(self._config.endpoint), content=body, headers=headers
                )
                async with asyncio.timeout(self._deadline_s):
                    resp = await self._client.send(request, stream=True)
                    got_response = True
                    try:
                        raw, digest = await self._read_capped(resp)
                    finally:
                        await resp.aclose()
            except AuthFailure as exc:
                result.error = TargetError(TargetErrorKind(exc.kind), str(exc))
                return
            except _TooLarge:
                result.http_status = resp.status_code
                result.error = TargetError(
                    TargetErrorKind.RESPONSE_TOO_LARGE, f"response exceeded {MAX_RESPONSE_BYTES} bytes"
                )
                return
            except (TimeoutError, httpx.TimeoutException) as exc:
                if (
                    not got_response
                    and isinstance(exc, (httpx.ConnectTimeout, httpx.PoolTimeout))
                    and net_retries < MAX_RETRIES
                ):
                    net_retries += 1
                    await self._backoff(net_retries)
                    continue
                result.error = TargetError(
                    TargetErrorKind.TIMEOUT, f"no complete response within {self._config.timeout_s}s"
                )
                return
            except httpx.HTTPError as exc:
                if (
                    not got_response
                    and isinstance(exc, _RETRYABLE_BEFORE_RESPONSE)
                    and net_retries < MAX_RETRIES
                ):
                    net_retries += 1
                    await self._backoff(net_retries)
                    continue
                result.error = TargetError(
                    TargetErrorKind.UNREACHABLE, f"request failed ({type(exc).__name__})"
                )
                return

            status = resp.status_code
            result.http_status = status
            result.response_bytes = len(raw)
            result.response_hash = digest

            if 200 <= status < 300:
                self._parse_success(raw, result)
                return

            if status == 401 and not reauthed:
                reauthed = True
                try:
                    if await self._auth.refresh_after_401(self._client):
                        continue
                except AuthFailure as exc:
                    result.error = TargetError(TargetErrorKind(exc.kind), str(exc))
                    return

            retry_after = parse_retry_after(resp.headers.get("retry-after"))
            if status == 429 or (status == 503 and retry_after is not None):
                wait = retry_after if retry_after is not None else BACKOFF_BASE_S * 2 ** (rate_waits + 1)
                if wait > self._config.timeout_s:
                    result.error = TargetError(
                        TargetErrorKind.RATE_LIMITED, f"HTTP {status}, Retry-After {wait:.0f}s too long"
                    )
                    return
                if rate_waits < MAX_RATE_LIMIT_WAITS:
                    rate_waits += 1
                    await self._limiter.penalize(self._config.target_id, wait)
                    await self._wait(wait)
                    continue
                kind = TargetErrorKind.RATE_LIMITED
                result.error = TargetError(kind, f"HTTP {status} after {rate_waits} waits")
                return

            if status >= 500:
                if net_retries < MAX_RETRIES:
                    net_retries += 1
                    await self._backoff(net_retries)
                    continue
                result.error = TargetError(TargetErrorKind.HTTP_5XX, f"HTTP {status}")
                return

            if 300 <= status < 400:
                result.error = TargetError(TargetErrorKind.HTTP_REDIRECT, f"HTTP {status}")
                return
            result.error = TargetError(TargetErrorKind.HTTP_4XX, f"HTTP {status}")
            return

    @staticmethod
    async def _read_capped(resp: httpx.Response) -> tuple[bytes, str]:
        hasher = hashlib.sha256()
        chunks: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise _TooLarge
            hasher.update(chunk)
            chunks.append(chunk)
        return b"".join(chunks), hasher.hexdigest()[:16]

    async def _backoff(self, attempt: int) -> None:
        await self._wait(BACKOFF_BASE_S * 2 ** (attempt - 1))

    # ── Response parsing ─────────────────────────────────────────────────────

    def _parse_success(self, raw: bytes, result: TurnResult) -> None:
        cfg = self._config
        if cfg.streaming == "none":
            try:
                data: Any = json.loads(raw)
            except (ValueError, RecursionError):
                result.error = TargetError(TargetErrorKind.BAD_JSON, "response is not valid JSON")
                return
            chunks = [data]
            text = self._extract_text(data)
        else:
            try:
                chunks = parse_stream(cfg.streaming, raw)
            except StreamParseError:
                result.error = TargetError(TargetErrorKind.BAD_JSON, "stream is not valid NDJSON")
                return
            text = assemble_text(chunks, cfg.response_path)

        self._capture_session_id(chunks)
        result.tool_calls = self._extract_tool_calls(chunks, text)

        if text is None:
            result.error = TargetError(
                TargetErrorKind.EXTRACT_FAILED, "no reply text found in response"
            )
            return
        result.response_text = text
        if cfg.session_mode == "server_session" and self._session_id is None:
            result.error = TargetError(
                TargetErrorKind.EXTRACT_FAILED, "no session id found at session_id_path"
            )

    def _extract_text(self, data: Any) -> str | None:
        if self._config.response_path:
            value = get_path(data, self._config.response_path)
            if isinstance(value, str):
                return value
        if isinstance(data, dict):
            for key in FALLBACK_KEYS:
                if isinstance(data.get(key), str):
                    return data[key]
        return None

    def _capture_session_id(self, chunks: list[Any]) -> None:
        path = self._config.session_id_path
        if self._config.session_mode != "server_session" or not path:
            return
        for chunk in chunks:
            value = get_path(chunk, path)
            if isinstance(value, (str, int)) and not isinstance(value, bool) and str(value):
                self._session_id = str(value)
                return

    def _extract_tool_calls(self, chunks: list[Any], text: str | None) -> list[ToolCallObservation]:
        path = self._config.tool_trace_path
        if path:
            calls: list[ToolCallObservation] = []
            for chunk in chunks:
                calls.extend(_structured_tool_calls(get_path(chunk, path)))
            return calls
        return _heuristic_tool_calls(text or "")
