"""Shared helpers for the test_session_adapter*.py suites (no tests here)."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from typing import Any

import httpx

from cyberredteam.contracts import TargetConfig
from cyberredteam.transport import InProcessTokenBucket, SessionAdapter

CAMPAIGN = "RX-test0001"


class FakeClock:
    """Deterministic clock + sleep; sleeping advances time without waiting."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class NoLimit:
    async def acquire(self, target_id: str) -> None:
        return None


def make_config(**overrides: Any) -> TargetConfig:
    data: dict[str, Any] = {
        "target_id": str(uuid.uuid4()),
        "name": "t",
        "endpoint": "http://fake-target.test/chat",
        "session_mode": "stateless_history",
        "environment": "staging",
    }
    data.update(overrides)
    return TargetConfig.model_validate(data)


def make_adapter(
    config: TargetConfig,
    transport: httpx.AsyncBaseTransport,
    *,
    clock: FakeClock | None = None,
    limiter: Any = None,
) -> SessionAdapter:
    clock = clock or FakeClock()
    return SessionAdapter(
        config,
        campaign_id=CAMPAIGN,
        rate_limiter=limiter or NoLimit(),
        transport=transport,
        sleep=clock.sleep,
        clock=clock,
    )


def bucket(rps: float, clock: FakeClock, burst: int = 1) -> InProcessTokenBucket:
    return InProcessTokenBucket(rps, burst, clock=clock, sleep=clock.sleep)


def run(coro: Any) -> Any:
    return asyncio.run(coro)


class Recorder:
    """MockTransport whose handler is a callable(request, n) -> Response."""

    def __init__(self, handler: Callable[[httpx.Request, int], httpx.Response]) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request, len(self.requests))
