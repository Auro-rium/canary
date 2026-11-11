"""Run control seam shared by the conversation engine (WP3) and the job layer (WP7).

Frozen interface: the engine calls :meth:`RunControl.check` before every turn.
WP7 provides the durable implementation (per-campaign cancel flag in Postgres
plus the global kill switch). The in-memory implementation here is for tests
and single-process dev runs.
"""

from __future__ import annotations

import asyncio
from typing import Literal, Protocol, runtime_checkable

StopSignal = Literal["cancelled", "killed"]


@runtime_checkable
class RunControl(Protocol):
    async def check(self, campaign_id: str) -> StopSignal | None:
        """Return a stop signal if the campaign must stop before its next turn.

        ``"killed"`` (global kill switch) takes precedence over ``"cancelled"``.
        Implementations must be cheap (called once per turn) and must fail
        closed: if the control state cannot be read, return ``"killed"``.
        """
        ...


class InMemoryRunControl:
    """Process-local run control. Not durable; tests and dev only."""

    def __init__(self) -> None:
        self._cancelled: set[str] = set()
        self._killed = False
        self._lock = asyncio.Lock()

    async def cancel(self, campaign_id: str) -> None:
        async with self._lock:
            self._cancelled.add(campaign_id)

    async def kill_all(self) -> None:
        async with self._lock:
            self._killed = True

    async def reset_kill_switch(self) -> None:
        async with self._lock:
            self._killed = False

    async def check(self, campaign_id: str) -> StopSignal | None:
        if self._killed:
            return "killed"
        if campaign_id in self._cancelled:
            return "cancelled"
        return None
