"""Durable run control: per-campaign cancel flag plus a global kill switch.

``DbRunControl`` implements the frozen ``engine.control.RunControl`` protocol.
Flags live in the ``run_control`` table so the API process (which sets them) and
worker processes (which read them before every turn) share state.

Rules, in order:

1. ``CANARY_KILL_SWITCH`` in the environment: ``"killed"``. Fail-safe parsing:
   any non-empty value other than 0/false/no/off counts as ON. A process's
   environment does not change while it runs, so this variant takes effect when
   the process (API or worker) starts; the DB flag is the live control.
2. DB kill-switch flag: ``"killed"``.
3. DB cancel flag for the campaign: ``"cancelled"``.
4. Any error reading the DB: ``"killed"`` (fail closed).

DB flags are read UNCACHED by default (one primary-key lookup per turn), so a
flag set by the API stops every conversation within one turn. ``cache_ttl`` > 0
is available for deployments that prefer fewer reads, at the cost of that
guarantee; the default is 0.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Callable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.engine.control import StopSignal
from cyberredteam.jobs.tables import CANCEL_PREFIX, KILL_SWITCH_KEY, RunControlRow
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.orm import utcnow

logger = logging.getLogger(__name__)

_FALSY = {"", "0", "false", "no", "off"}


def env_kill_switch_active() -> bool:
    """True for any value other than unset/empty/0/false/no/off (fails safe)."""
    return os.environ.get("CANARY_KILL_SWITCH", "").strip().lower() not in _FALSY


class ControlStore:
    """Sync reads/writes of the control flags."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def _set(self, key: str, enabled: bool, actor: str | None) -> None:
        with session_scope(self._factory) as s:
            row = s.get(RunControlRow, key)
            if row is None:
                s.add(RunControlRow(key=key, enabled=enabled, updated_by=actor, updated_at=utcnow()))
            else:
                row.enabled = enabled
                row.updated_by = actor
                row.updated_at = utcnow()

    def set_kill_switch(self, enabled: bool, actor: str | None = None) -> None:
        self._set(KILL_SWITCH_KEY, enabled, actor)

    def kill_switch_state(self) -> tuple[bool, str | None, datetime | None]:
        with session_scope(self._factory) as s:
            row = s.get(RunControlRow, KILL_SWITCH_KEY)
            if row is None:
                return False, None, None
            return bool(row.enabled), row.updated_by, row.updated_at

    def request_cancel(self, campaign_id: str, actor: str | None = None) -> None:
        self._set(CANCEL_PREFIX + campaign_id, True, actor)

    def cancel_requested(self, campaign_id: str) -> bool:
        with session_scope(self._factory) as s:
            row = s.get(RunControlRow, CANCEL_PREFIX + campaign_id)
            return bool(row and row.enabled)

    def read_signal(self, campaign_id: str) -> StopSignal | None:
        """One query on the primary key for both flags; ``killed`` wins."""
        keys = (KILL_SWITCH_KEY, CANCEL_PREFIX + campaign_id)
        with session_scope(self._factory) as s:
            rows = {
                r.key: bool(r.enabled)
                for r in s.scalars(select(RunControlRow).where(RunControlRow.key.in_(keys)))
            }
        if rows.get(KILL_SWITCH_KEY):
            return "killed"
        if rows.get(CANCEL_PREFIX + campaign_id):
            return "cancelled"
        return None


class DbRunControl:
    """``RunControl`` backed by the ``run_control`` table. See module docstring."""

    def __init__(
        self,
        factory: sessionmaker[Session],
        *,
        cache_ttl: float = 0.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = ControlStore(factory)
        self._ttl = max(0.0, cache_ttl)
        self._clock = clock
        self._cache: dict[str, tuple[float, StopSignal | None]] = {}

    @property
    def store(self) -> ControlStore:
        return self._store

    def invalidate(self) -> None:
        """Drop cached reads (only relevant when ``cache_ttl`` > 0)."""
        self._cache.clear()

    async def check(self, campaign_id: str) -> StopSignal | None:
        if env_kill_switch_active():
            return "killed"
        now = self._clock()
        if self._ttl > 0:
            hit = self._cache.get(campaign_id)
            if hit is not None and hit[0] > now:
                return hit[1]
        try:
            signal = await asyncio.to_thread(self._store.read_signal, campaign_id)
        except Exception as exc:  # fail closed on ANY read error
            logger.error("run control read failed (%s); failing closed", type(exc).__name__)
            signal = "killed"
        if self._ttl > 0:
            if len(self._cache) > 4096:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
            self._cache[campaign_id] = (now + self._ttl, signal)
        return signal
