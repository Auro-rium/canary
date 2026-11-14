"""Worker heartbeats and the stale-run reaper (resume on restart).

Resume strategy (documented choice): ``engine.runner.run_campaign`` is
idempotent and continues from persisted turns, so resuming a campaign after a
worker crash or restart is simply *running it again*. We do not use the
LangGraph PostgresSaver. A worker writes a heartbeat row per campaign it is
running; the reaper finds campaigns in status ``running`` whose heartbeat is
missing or older than the stale threshold and re-enqueues them.

Exclusivity does NOT rely on a procrastinate ``lock`` (a SIGKILLed worker leaves
its job in ``doing`` holding the lock, which would block the resume job
forever). Instead :meth:`HeartbeatRepo.claim` is the lock: it is row-locked
(``SELECT ... FOR UPDATE`` on Postgres) and IntegrityError-safe, and a claim
only succeeds when no other worker's heartbeat is fresh. The queue keeps a
``queueing_lock`` so at most one resume job per campaign is *waiting*.

While the kill switch is on the reaper does not resume anything: it marks stale
``running`` campaigns ``cancelled`` (event reason ``kill_switch``, audit row).
The audit row ``campaign.resume_enqueued`` is only written when a job was
actually enqueued.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.contracts import CampaignCancelledPayload
from cyberredteam.jobs.control import ControlStore, env_kill_switch_active
from cyberredteam.jobs.events import EventLog
from cyberredteam.jobs.tables import CampaignHeartbeatRow
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.orm import utcnow
from cyberredteam.storage.v2.repositories import AuditRepo, CampaignRepo

logger = logging.getLogger(__name__)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class HeartbeatRepo:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def beat(self, campaign_id: str, worker_id: str | None) -> None:
        with session_scope(self._factory) as s:
            row = s.get(CampaignHeartbeatRow, campaign_id)
            if row is None:
                s.add(CampaignHeartbeatRow(campaign_id=campaign_id, worker_id=worker_id, beat_at=utcnow()))
            else:
                row.worker_id = worker_id
                row.beat_at = utcnow()

    def claim(self, campaign_id: str, worker_id: str, stale_after_s: float) -> bool:
        """Take the campaign unless another worker's heartbeat is still fresh.

        A row with ``worker_id=None`` (touched by the reaper) is claimable.
        Row-locked on Postgres; a concurrent first insert loses on the primary
        key and re-evaluates.
        """
        for _ in range(3):
            try:
                with session_scope(self._factory) as s:
                    row = s.scalars(
                        select(CampaignHeartbeatRow)
                        .where(CampaignHeartbeatRow.campaign_id == campaign_id)
                        .with_for_update()
                    ).first()
                    now = utcnow()
                    if row is not None and row.worker_id not in (None, worker_id):
                        if _aware(row.beat_at) > now - timedelta(seconds=stale_after_s):
                            return False
                    if row is None:
                        s.add(CampaignHeartbeatRow(campaign_id=campaign_id, worker_id=worker_id, beat_at=now))
                    else:
                        row.worker_id = worker_id
                        row.beat_at = now
                    return True
            except IntegrityError:
                continue  # someone inserted the row first; look at it now
        return False

    def release(self, campaign_id: str) -> None:
        with session_scope(self._factory) as s:
            row = s.get(CampaignHeartbeatRow, campaign_id)
            if row is not None:
                s.delete(row)

    def get(self, campaign_id: str) -> tuple[str | None, datetime] | None:
        with session_scope(self._factory) as s:
            row = s.get(CampaignHeartbeatRow, campaign_id)
            return (row.worker_id, _aware(row.beat_at)) if row else None

    def stale_running(self, stale_after_s: float) -> list[str]:
        """Campaigns in status ``running`` with no heartbeat or a stale one."""
        cutoff = utcnow() - timedelta(seconds=stale_after_s)
        with session_scope(self._factory) as s:
            running = list(
                s.scalars(select(orm.CampaignRow.campaign_id).where(orm.CampaignRow.status == "running"))
            )
            beats = {
                r.campaign_id: _aware(r.beat_at)
                for r in s.scalars(
                    select(CampaignHeartbeatRow).where(CampaignHeartbeatRow.campaign_id.in_(running))
                )
            } if running else {}
        return [c for c in running if c not in beats or beats[c] < cutoff]


@dataclass
class ReapResult:
    resumed: list[str] = field(default_factory=list)
    cancelled: list[str] = field(default_factory=list)


async def reap_stale(
    factory: sessionmaker[Session],
    queue,  # JobQueue; enqueue_campaign returns True only if a job was enqueued
    stale_after_s: float,
) -> ReapResult:
    """Resume orphaned running campaigns (or cancel them while the kill switch is on)."""
    result = ReapResult()
    beats = HeartbeatRepo(factory)
    audit = AuditRepo(factory)
    campaigns = CampaignRepo(factory)
    events = EventLog(factory)

    killed = env_kill_switch_active()
    if not killed:
        try:
            killed, _, _ = await asyncio.to_thread(ControlStore(factory).kill_switch_state)
        except Exception:
            logger.error("reaper could not read kill switch; skipping (fail closed)")
            return result

    stale = await asyncio.to_thread(beats.stale_running, stale_after_s)
    for campaign_id in stale:
        if killed:
            await asyncio.to_thread(campaigns.set_status, campaign_id, "cancelled")
            if not await asyncio.to_thread(events.has_terminal, campaign_id):
                await asyncio.to_thread(
                    events.append, campaign_id, "campaign_cancelled",
                    CampaignCancelledPayload(campaign_id=campaign_id, reason="kill_switch"),
                )
            await asyncio.to_thread(beats.release, campaign_id)
            await asyncio.to_thread(
                audit.record, "reaper", "campaign.killed", f"campaign:{campaign_id}",
                {"stale_after_s": stale_after_s},
            )
            logger.warning("kill switch on: cancelled stale campaign %s", campaign_id)
            result.cancelled.append(campaign_id)
            continue
        await asyncio.to_thread(beats.beat, campaign_id, None)
        try:
            enqueued = await queue.enqueue_campaign(campaign_id)
        except Exception as exc:
            logger.error("could not re-enqueue %s (%s)", campaign_id, type(exc).__name__)
            continue
        if enqueued:
            await asyncio.to_thread(
                audit.record, "reaper", "campaign.resume_enqueued", f"campaign:{campaign_id}",
                {"stale_after_s": stale_after_s},
            )
            logger.warning("re-enqueued stale campaign %s", campaign_id)
            result.resumed.append(campaign_id)
    return result
