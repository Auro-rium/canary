"""SessionAdapter per-request gate (WP3 review): every HTTP request, retries and
auth sub-requests included, passes the before_attempt hook and the rate limiter,
and cancel() interrupts retry waits."""

from __future__ import annotations

import asyncio

import httpx
from fixtures.fake_target import FakeTarget
from test_session_adapter_support import FakeClock, NoLimit, make_adapter, make_config, run

from cyberredteam.transport import SendAborted, SessionAdapter, TargetErrorKind


class CountingLimiter(NoLimit):
    def __init__(self) -> None:
        super().__init__()
        self.acquired = 0

    async def acquire(self, target_id: str) -> None:
        self.acquired += 1


def _adapter(config, transport, hook, limiter=None, sleep=None):
    clock = FakeClock()
    return SessionAdapter(
        config, campaign_id="RX-gate", rate_limiter=limiter or NoLimit(), transport=transport,
        sleep=sleep or clock.sleep, clock=clock, before_attempt=hook,
    )


def test_hook_runs_before_every_attempt_including_retries():
    fake = FakeTarget(profile="flaky_500", fail_first=2)
    calls = []

    async def hook():
        calls.append(len(fake.requests))

    adapter = _adapter(fake.target_config(), fake.transport(), hook)
    result = run(adapter.send("hello"))
    assert result.ok and result.attempts == 3
    assert calls == [0, 1, 2]  # always before the request it gates


def test_auth_sub_requests_are_gated_and_rate_limited():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "t0k", "expires_in": 3600})
        return httpx.Response(200, json={"reply": "ok"})

    config = make_config(
        response_path="reply",
        auth={"type": "oauth_client_credentials", "token_url": "http://fake-target.test/token",
              "client_id": "c", "client_secret": "s3cret"},
    )
    hook_calls = []

    async def hook():
        hook_calls.append(len(seen))

    limiter = CountingLimiter()
    adapter = _adapter(config, httpx.MockTransport(handler), hook, limiter)
    assert run(adapter.send("hello")).ok
    assert seen == ["/token", "/chat"]
    # Main-attempt gate (nothing sent yet), then the token fetch's gate.
    assert hook_calls == [0, 0] and limiter.acquired == 2


def test_hook_refusal_stops_further_requests():
    fake = FakeTarget(profile="flaky_500", fail_first=10)
    calls = 0

    async def hook():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise SendAborted("budget")

    adapter = _adapter(fake.target_config(), fake.transport(), hook)
    result = run(adapter.send("hello"))
    assert result.error and result.error.kind is TargetErrorKind.CANCELLED
    assert "budget" in result.error.message
    assert len(fake.requests) == 1


def test_cancel_interrupts_retry_backoff():
    fake = FakeTarget(profile="flaky_500", fail_first=10)
    forever = asyncio.Event()

    async def blocking_sleep(seconds: float) -> None:
        await forever.wait()

    adapter = _adapter(fake.target_config(), fake.transport(), None, sleep=blocking_sleep)

    async def go():
        task = asyncio.create_task(adapter.send("hello"))
        while not fake.requests:
            await asyncio.sleep(0)
        await asyncio.sleep(0)
        adapter.cancel()
        return await asyncio.wait_for(task, 2)

    result = run(go())
    assert result.error and result.error.kind is TargetErrorKind.CANCELLED
    assert len(fake.requests) == 1


def test_default_adapter_without_hook_unchanged():
    fake = FakeTarget()
    adapter = make_adapter(fake.target_config(), fake.transport())
    assert run(adapter.send("hello")).ok
