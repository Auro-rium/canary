"""Per-target rate limiting for the session adapter.

``RateLimiter`` is the seam: WP7 adds a distributed implementation (Redis or a
Postgres advisory lock) behind the same protocol. ``InProcessTokenBucket`` is
the in-process one, shared by every adapter that is handed the same instance.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Protocol, runtime_checkable


@runtime_checkable
class RateLimiter(Protocol):
    async def acquire(self, target_id: str) -> None:
        """Return once one request to ``target_id`` may be sent."""
        ...

    async def penalize(self, target_id: str, seconds: float) -> None:
        """The target asked us to back off (429/503 Retry-After): hold every
        caller for ``target_id`` for at least ``seconds``."""
        ...


class InProcessTokenBucket:
    """Token bucket keyed by ``target_id``: ``rps`` tokens/s, up to ``burst`` stored.

    Waiters for the same target are served one at a time, so concurrent
    conversations against one target share its budget. ``clock`` and ``sleep``
    are injectable for tests.
    """

    def __init__(
        self,
        rps: float,
        burst: int = 1,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if rps <= 0:
            raise ValueError("rps must be > 0")
        if burst < 1:
            raise ValueError("burst must be >= 1")
        self._rps = float(rps)
        self._burst = float(burst)
        self._clock = clock
        self._sleep = sleep
        self._tokens: dict[str, float] = {}
        self._stamp: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._blocked_until: dict[str, float] = {}

    async def penalize(self, target_id: str, seconds: float) -> None:
        until = self._clock() + max(0.0, seconds)
        self._blocked_until[target_id] = max(self._blocked_until.get(target_id, 0.0), until)

    async def acquire(self, target_id: str) -> None:
        lock = self._locks.setdefault(target_id, asyncio.Lock())
        async with lock:
            while True:
                now = self._clock()
                blocked = self._blocked_until.get(target_id, 0.0) - now
                if blocked > 0:
                    await self._sleep(blocked)
                    continue
                tokens = self._tokens.get(target_id, self._burst)
                last = self._stamp.get(target_id, now)
                tokens = min(self._burst, tokens + (now - last) * self._rps)
                self._stamp[target_id] = now
                if tokens >= 1.0 - 1e-9:
                    self._tokens[target_id] = tokens - 1.0
                    return
                self._tokens[target_id] = tokens
                await self._sleep((1.0 - tokens) / self._rps)
