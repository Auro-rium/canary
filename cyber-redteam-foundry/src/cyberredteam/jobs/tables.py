"""ORM tables owned by WP7 (migration revision 0002).

They live on the shared ``storage.v2.orm.Base`` so Alembic autogenerate and the
schema-drift test see them; ``storage/v2/orm.py`` itself is untouched.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from cyberredteam.storage.v2.orm import Base, utcnow

KILL_SWITCH_KEY = "kill_switch"
CANCEL_PREFIX = "cancel:"


class RunControlRow(Base):
    """Control flags. ``kill_switch`` is global; ``cancel:<campaign_id>`` is per campaign."""

    __tablename__ = "run_control"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CampaignHeartbeatRow(Base):
    __tablename__ = "campaign_heartbeats"

    campaign_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("campaigns.campaign_id", ondelete="CASCADE"), primary_key=True
    )
    worker_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    beat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CampaignEventRow(Base):
    """Persisted SSE event log; ``seq`` is the per-campaign ``Last-Event-ID``."""

    __tablename__ = "campaign_events"
    __table_args__ = (UniqueConstraint("campaign_id", "seq", name="uq_campaign_event_seq"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("campaigns.campaign_id", ondelete="CASCADE")
    )
    seq: Mapped[int] = mapped_column(Integer)
    type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
