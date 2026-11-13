"""Worker heartbeats and the stale-run reaper (resume on restart).

Resume strategy (documented choice): ``engine.runner.run_campaign`` is
idempotent and continues from persisted turns, so resuming a campaign after a
worker crash or restart is simply *running it again*. We do not use the
LangGraph PostgresSaver. A worker writes a heartbeat row per campaign it is
running; the reaper finds campaigns in status ``running`` whose heartbeat is
missing or older than the stale threshold and re-enqueues them.

Safety: the reaper does nothing while the kill switch is on, claims the
campaign by touching its heartbeat before enqueueing (so it is not re-enqueued
every tick), and the queue uses a per-campaign ``lock`` and ``queueing_lock`` so
two jobs for one campaign never run or sit queued together.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.jobs.control import ControlStore, env_kill_switch_active
from cyberredteam.jobs.tables import CampaignHeartbeatRow
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.orm import utcnow
from cyberredteam.storage.v2.repositories import AuditRepo

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
        """
        with session_scope(self._factory) as s:
            row = s.get(CampaignHeartbeatRow, campaign_id)
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


async def reap_stale(
    factory: sessionmaker[Session],
    queue,  # JobQueue
    stale_after_s: float,
) -> list[str]:
    """Re-enqueue orphaned running campaigns. Returns the campaign ids enqueued."""
    import asyncio

    if env_kill_switch_active():
        return []
    try:
        killed, _, _ = await asyncio.to_thread(ControlStore(factory).kill_switch_state)
    except Exception:
        logger.error("reaper could not read kill switch; skipping (fail closed)")
        return []
    if killed:
        return []
    beats = HeartbeatRepo(factory)
    audit = AuditRepo(factory)
    stale = await asyncio.to_thread(beats.stale_running, stale_after_s)
    resumed: list[str] = []
    for campaign_id in stale:
        await asyncio.to_thread(beats.beat, campaign_id, None)
        await queue.enqueue_campaign(campaign_id)
        await asyncio.to_thread(
            audit.record, "reaper", "campaign.resume_enqueued", f"campaign:{campaign_id}",
            {"stale_after_s": stale_after_s},
        )
        logger.warning("re-enqueued stale campaign %s", campaign_id)
        resumed.append(campaign_id)
    return resumed
