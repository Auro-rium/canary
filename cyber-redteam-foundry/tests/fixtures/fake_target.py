"""Test-only stateful fake HTTP agent (WP0).

An in-process stand-in for an operator-owned chat agent, used to test the
session adapter, conversation engine and monitors without any network. It is
test infrastructure: every reply is benign placeholder text, the "canary" is a
configured marker string, and the "forbidden tool" is just a name.

Wire contract (``POST {path}``, JSON):

* request  ``{"message": str, "messages"?: [{role, content}], "session_id"?: str}``
* response ``{"reply": str, "turn": int, "tool_calls": [{name, arguments, call_id}],
  "session_id"?: str}``

Session modes decide how the turn number of a conversation is known:

* ``stateless_history``: no server state; ``messages`` must carry the whole
  OpenAI-style history and the turn is the number of ``user`` entries.
* ``server_session``: a request without ``session_id`` (or with null/"") opens a
  new session and the id is returned in ``session_id``. Sending it back
  advances that session; an unknown id is a 404.
* ``cookie``: as above, but the id travels in the ``fake_sid`` cookie.

Behaviour profiles (``t`` is the 1-based turn within a conversation):

* ``always_safe``: a fixed polite reply every turn.
* ``leaks_after_n_turns``: turns ``t > n_turns`` include ``canary``.
* ``tool_misuse_on_turn_k``: turn ``k`` reports a benign tool call plus
  ``forbidden_tool`` in ``tool_calls``.
* ``flaky_500``: deterministic failures (``fail_first`` then every
  ``fail_every``-th request) return 500. Failed requests never advance or
  create a session.
* ``slow``: waits ``delay_s``. Under ``MockTransport``, if ``delay_s`` exceeds
  the client's read timeout it raises ``httpx.ReadTimeout`` instead of waiting.
* ``session_server``: safe replies that state the session turn; requires
  ``server_session`` mode. An adapter that forgets the id never gets past turn
  1, and ``sessions_issued`` shows it.

Usage::

    fake = FakeTarget(profile="leaks_after_n_turns", n_turns=2)
    client = httpx.Client(transport=fake.transport())          # sync or async
    client = httpx.AsyncClient(transport=fake.async_transport())  # real sleeps
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=fake.asgi_app()))
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

from cyberredteam.contracts import TargetConfig

Profile = Literal[
    "always_safe",
    "leaks_after_n_turns",
    "tool_misuse_on_turn_k",
    "flaky_500",
    "slow",
    "session_server",
]
Mode = Literal["stateless_history", "server_session", "cookie"]

BASE_URL = "http://fake-target.test"
DEFAULT_PATH = "/chat"
COOKIE_NAME = "fake_sid"
DEFAULT_CANARY = "CANARY-TEST-0001"
DEFAULT_FORBIDDEN_TOOL = "delete_record"
BENIGN_TOOL = "lookup_order_status"
SAFE_REPLY = "Thanks for your message. I can help with general questions about this demo service."

REQUEST_TEMPLATES: dict[str, str] = {
    "stateless_history": '{"message": "{{MESSAGE}}", "messages": "{{HISTORY}}"}',
    "server_session": '{"message": "{{MESSAGE}}", "session_id": "{{SESSION_ID}}"}',
    "cookie": '{"message": "{{MESSAGE}}"}',
}


@dataclass
class RecordedRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: Any
    status: int


@dataclass
class FakeResponse:
    status: int
    body: dict[str, Any]
    headers: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class FakeTarget:
    profile: Profile = "always_safe"
    session_mode: Mode = "stateless_history"
    n_turns: int = 2
    canary: str = DEFAULT_CANARY
    k: int = 2
    forbidden_tool: str = DEFAULT_FORBIDDEN_TOOL
    fail_first: int = 1
    fail_every: int = 0
    delay_s: float = 0.05
    path: str = DEFAULT_PATH
    required_headers: dict[str, str] = field(default_factory=dict)

    requests: list[RecordedRequest] = field(default_factory=list, init=False)
    sessions: dict[str, int] = field(default_factory=dict, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.profile == "session_server" and self.session_mode != "server_session":
            raise ValueError("profile 'session_server' requires session_mode='server_session'")
        if self.n_turns < 0 or self.k < 1 or self.fail_first < 0 or self.fail_every < 0:
            raise ValueError("n_turns >= 0, k >= 1, fail_first >= 0, fail_every >= 0")

    # ── Introspection ────────────────────────────────────────────────────────

    @property
    def url(self) -> str:
        return BASE_URL + self.path

    @property
    def sessions_issued(self) -> int:
        return len(self.sessions)

    def successful_requests(self) -> list[RecordedRequest]:
        return [r for r in self.requests if 200 <= r.status < 300]

    def target_config(self, **overrides: Any) -> TargetConfig:
        """A TargetConfig matching this fake's wire contract and session mode."""
        data: dict[str, Any] = {
            "target_id": str(uuid.uuid4()),
            "name": f"fake-{self.profile}",
            "endpoint": self.url,
            "request_template": REQUEST_TEMPLATES[self.session_mode],
            "response_path": "reply",
            "session_mode": self.session_mode,
            "session_id_path": "session_id" if self.session_mode == "server_session" else None,
            "tool_trace_path": "tool_calls",
            "environment": "staging",
        }
        data.update(overrides)
        return TargetConfig.model_validate(data)

    # ── Core (transport-agnostic) ────────────────────────────────────────────

    def handle(self, method: str, path: str, headers: dict[str, str], raw_body: bytes) -> FakeResponse:
        headers = {k.lower(): v for k, v in headers.items()}
        try:
            body: Any = json.loads(raw_body or b"null")
        except ValueError:
            body = None
        with self._lock:
            resp = self._handle_locked(method, path, headers, body)
            self.requests.append(RecordedRequest(method, path, headers, body, resp.status))
        return resp

    def _handle_locked(self, method: str, path: str, headers: dict[str, str], body: Any) -> FakeResponse:
        if path != self.path:
            return FakeResponse(404, {"error": "not found"})
        if method != "POST":
            return FakeResponse(405, {"error": "method not allowed"})
        for name, value in self.required_headers.items():
            if headers.get(name.lower()) != value:
                return FakeResponse(401, {"error": "unauthorized"})
        if not isinstance(body, dict) or not isinstance(body.get("message"), str):
            return FakeResponse(400, {"error": "body must be JSON with a string 'message'"})

        if self.profile == "flaky_500" and self._should_fail(len(self.requests) + 1):
            return FakeResponse(500, {"error": "temporary failure"})

        resp_headers: list[tuple[str, str]] = []
        session_id: str | None = None
        if self.session_mode == "stateless_history":
            msgs = body.get("messages")
            if (
                not isinstance(msgs, list)
                or not msgs
                or not all(isinstance(m, dict) for m in msgs)
                or msgs[-1].get("role") != "user"
            ):
                return FakeResponse(400, {"error": "'messages' history ending in a user turn required"})
            turn = sum(1 for m in msgs if m.get("role") == "user")
        else:
            if self.session_mode == "server_session":
                sent = body.get("session_id") or None
            else:
                sent = _read_cookie(headers.get("cookie", ""), COOKIE_NAME)
            if sent is None:
                session_id = uuid.uuid4().hex[:12]
                self.sessions[session_id] = 0
                if self.session_mode == "cookie":
                    resp_headers.append(("set-cookie", f"{COOKIE_NAME}={session_id}; Path=/"))
            elif sent not in self.sessions:
                return FakeResponse(404, {"error": "unknown session"})
            else:
                session_id = sent
            self.sessions[session_id] += 1
            turn = self.sessions[session_id]

        out: dict[str, Any] = {"reply": self._reply(turn), "turn": turn, "tool_calls": self._tools(turn)}
        if self.session_mode == "server_session":
            out["session_id"] = session_id
        return FakeResponse(200, out, resp_headers)

    def _should_fail(self, request_number: int) -> bool:
        if request_number <= self.fail_first:
            return True
        return bool(self.fail_every) and (request_number - self.fail_first) % self.fail_every == 0

    def _reply(self, turn: int) -> str:
        if self.profile == "leaks_after_n_turns" and turn > self.n_turns:
            return f"{SAFE_REPLY} Reference: {self.canary}"
        if self.profile == "session_server":
            return f"{SAFE_REPLY} (session turn {turn})"
        return SAFE_REPLY

    def _tools(self, turn: int) -> list[dict[str, Any]]:
        if self.profile == "tool_misuse_on_turn_k" and turn == self.k:
            return [
                {"name": BENIGN_TOOL, "arguments": {"order_id": "placeholder-1"}, "call_id": f"call-{turn}-a"},
                {"name": self.forbidden_tool, "arguments": {"record_id": "placeholder-1"}, "call_id": f"call-{turn}-b"},
            ]
        return []

    # ── Transports ───────────────────────────────────────────────────────────

    def _to_httpx(self, request: httpx.Request, resp: FakeResponse) -> httpx.Response:
        return httpx.Response(resp.status, json=resp.body, headers=resp.headers, request=request)

    def _check_timeout(self, request: httpx.Request) -> None:
        read_timeout = (request.extensions.get("timeout") or {}).get("read")
        if read_timeout is not None and self.delay_s > read_timeout:
            raise httpx.ReadTimeout("fake target read timeout", request=request)

    def _dispatch(self, request: httpx.Request) -> httpx.Response:
        resp = self.handle(request.method, request.url.path, dict(request.headers), request.content)
        return self._to_httpx(request, resp)

    def transport(self) -> httpx.MockTransport:
        """Sync handler; works with ``httpx.Client`` and ``httpx.AsyncClient``."""

        def handler(request: httpx.Request) -> httpx.Response:
            if self.profile == "slow":
                self._check_timeout(request)
                time.sleep(self.delay_s)
            return self._dispatch(request)

        return httpx.MockTransport(handler)

    def async_transport(self) -> httpx.MockTransport:
        """Async handler (``asyncio.sleep`` for ``slow``); ``httpx.AsyncClient`` only."""

        async def handler(request: httpx.Request) -> httpx.Response:
            if self.profile == "slow":
                self._check_timeout(request)
                await asyncio.sleep(self.delay_s)
            return self._dispatch(request)

        return httpx.MockTransport(handler)

    def asgi_app(self) -> Any:
        """A tiny Starlette app with the same behaviour (no timeout simulation)."""
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route

        async def endpoint(request: Request) -> JSONResponse:
            if self.profile == "slow":
                await asyncio.sleep(self.delay_s)
            raw = await request.body()
            resp = self.handle(request.method, request.url.path, dict(request.headers), raw)
            response = JSONResponse(resp.body, status_code=resp.status)
            for name, value in resp.headers:
                response.headers.append(name, value)
            return response

        return Starlette(routes=[Route("/{path:path}", endpoint, methods=["GET", "POST", "PUT"])])


def _read_cookie(header: str, name: str) -> str | None:
    for part in header.split(";"):
        key, _, value = part.strip().partition("=")
        if key == name and value:
            return value
    return None


def history(*user_messages: str) -> list[dict[str, str]]:
    """OpenAI-style history with a placeholder assistant reply between user turns."""
    out: list[dict[str, str]] = []
    for i, text in enumerate(user_messages):
        if i:
            out.append({"role": "assistant", "content": SAFE_REPLY})
        out.append({"role": "user", "content": text})
    return out
