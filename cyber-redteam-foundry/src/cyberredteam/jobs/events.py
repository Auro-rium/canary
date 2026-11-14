"""Persisted campaign event log backing SSE resume (``Last-Event-ID`` = ``seq``).

Events follow the frozen section-2 contract (``contracts._Event``): the wire
form is ``to_sse()`` = ``{type, payload, timestamp, seq}``. Only contract event
types are accepted. Every payload is validated through the contract models on
the way in, which also applies their preview caps (``truncate_preview``), so a
sink can never persist an oversized preview.

Events are appended by whoever runs the campaign (worker process) and read by
the API process, so live streaming is a poll of this table. A client
disconnecting only stops its own polling; the run is unaffected.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timezone
from typing import Any

from pydantic import BaseModel, ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.contracts import SSE_EVENT_ADAPTER, SSE_EVENT_TYPES, SseEventType
from cyberredteam.jobs.tables import CampaignEventRow
from cyberredteam.storage.v2.db import session_scope

logger = logging.getLogger(__name__)

TERMINAL_EVENT_TYPES = frozenset({"campaign_complete", "campaign_failed", "campaign_cancelled"})
MAX_SEQ = 2**31 - 1  # seq is a 32-bit column


class EventLog:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    @staticmethod
    def _validated(event_type: str, payload: BaseModel | dict[str, Any]) -> dict[str, Any]:
        """Run the payload through the contract event model; returns the capped payload."""
        if event_type not in SSE_EVENT_TYPES:
            raise ValueError(f"not a contract SSE event type: {event_type!r}")
        data = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
        event = SSE_EVENT_ADAPTER.validate_python({"type": event_type, "payload": data, "seq": 0})
        return event.payload.model_dump(mode="json")

    def append(
        self, campaign_id: str, event_type: SseEventType, payload: BaseModel | dict[str, Any]
    ) -> int:
        """Validate and append an event; returns its per-campaign ``seq`` (1-based)."""
        data = self._validated(event_type, payload)
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
                            campaign_id=campaign_id, seq=seq, type=event_type, payload=data
                        )
                    )
                return seq
            except IntegrityError:
                # Lost a race on (campaign_id, seq); retry. A bad campaign FK
                # fails every attempt and surfaces after the loop.
                continue
        raise RuntimeError("could not append campaign event")

    def since(self, campaign_id: str, after_seq: int = 0, limit: int = 500) -> list[Any]:
        """Contract events (``contracts._Event`` subclasses) with ``seq > after_seq``."""
        with session_scope(self._factory) as s:
            rows = s.scalars(
                select(CampaignEventRow)
                .where(CampaignEventRow.campaign_id == campaign_id, CampaignEventRow.seq > after_seq)
                .order_by(CampaignEventRow.seq)
                .limit(limit)
            ).all()
            raw = [(r.type, r.payload, r.seq, r.created_at) for r in rows]
        out: list[Any] = []
        for etype, payload, seq, created in raw:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            try:
                out.append(
                    SSE_EVENT_ADAPTER.validate_python(
                        {"type": etype, "payload": payload, "seq": seq, "timestamp": created}
                    )
                )
            except ValidationError:
                logger.error("stored event %s/%s no longer matches the contract; skipped", campaign_id, seq)
        return out

    def has_terminal(self, campaign_id: str) -> bool:
        with session_scope(self._factory) as s:
            return (
                s.scalar(
                    select(func.count())
                    .select_from(CampaignEventRow)
                    .where(
                        CampaignEventRow.campaign_id == campaign_id,
                        CampaignEventRow.type.in_(TERMINAL_EVENT_TYPES),
                    )
                )
                or 0
            ) > 0


class EventLogSink:
    """``engine.types.EventSink`` that persists contract events to the log.

    The campaign id comes from the payload (every contract payload carries it).
    """

    def __init__(self, log: EventLog) -> None:
        self._log = log

    async def emit(self, event_type: SseEventType, payload: BaseModel) -> None:
        campaign_id = getattr(payload, "campaign_id", None)
        if not campaign_id:
            raise ValueError("event payload has no campaign_id")
        await asyncio.to_thread(self._log.append, campaign_id, event_type, payload)
