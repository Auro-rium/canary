"""Persisted campaign event log backing SSE resume (``Last-Event-ID`` = ``seq``).

Events are appended by whoever runs the campaign (worker process) and read by
the API process, so live streaming is a poll of this table. A client
disconnecting only stops its own polling; the run is unaffected.

Payloads must already be redacted by the emitter; this log is shown in UIs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.jobs.tables import CampaignEventRow
from cyberredteam.storage.v2.db import session_scope

TERMINAL_EVENT_TYPES = frozenset(
    {"campaign_completed", "campaign_failed", "campaign_cancelled", "campaign_killed"}
)


class CampaignEvent(BaseModel):
    campaign_id: str
    seq: int
    type: str
    payload: dict[str, Any]
    created_at: datetime


class EventLog:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def append(self, campaign_id: str, type: str, payload: dict[str, Any] | None = None) -> int:
        """Append an event and return its per-campaign ``seq`` (1-based)."""
        for _ in range(8):
            try:
                with session_scope(self._factory) as s:
                    last = s.scalar(
                        select(func.max(CampaignEventRow.seq)).where(
                            CampaignEventRow.campaign_id == campaign_id
                        )
                    )
                    seq = int(last or 0) + 1
                    s.add(
                        CampaignEventRow(
                            campaign_id=campaign_id, seq=seq, type=type, payload=payload or {}
                        )
                    )
                return seq
            except IntegrityError:
                # Lost a race on (campaign_id, seq); retry. A bad campaign FK
                # fails every attempt and surfaces after the loop.
                continue
        raise RuntimeError("could not append campaign event")

    def since(self, campaign_id: str, after_seq: int = 0, limit: int = 500) -> list[CampaignEvent]:
        with session_scope(self._factory) as s:
            rows = s.scalars(
                select(CampaignEventRow)
                .where(CampaignEventRow.campaign_id == campaign_id, CampaignEventRow.seq > after_seq)
                .order_by(CampaignEventRow.seq)
                .limit(limit)
            ).all()
            return [
                CampaignEvent(
                    campaign_id=r.campaign_id, seq=r.seq, type=r.type, payload=r.payload,
                    created_at=r.created_at,
                )
                for r in rows
            ]
