"""API v2 control-plane routes (WP7): cancel, kill switch, SSE events with resume.

Included by ``cyberredteam.api`` on the main app, so the app-wide
``require_auth`` dependency protects every route here.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.contracts import CampaignCancelledPayload
from cyberredteam.jobs.control import ControlStore, DbRunControl, env_kill_switch_active
from cyberredteam.jobs.events import MAX_SEQ, TERMINAL_EVENT_TYPES, EventLog
from cyberredteam.observability.hooks import get_metrics
from cyberredteam.settings import get_settings
from cyberredteam.storage.v2.db import make_session_factory
from cyberredteam.storage.v2.repositories import (
    TERMINAL_CAMPAIGN_STATUSES,
    AuditRepo,
    CampaignRepo,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# TODO(WP8): replace with the authenticated principal and require an admin role
# for the kill switch and an operator role for cancel. Until WP8 the single
# bearer token has no identity, so audit rows carry this fixed actor.
API_ACTOR = "api-token"


class ControlPlane:
    """The API's handles on the shared DB: flags, events, audit, campaigns."""

    def __init__(self, factory: sessionmaker[Session], poll_interval_s: float = 0.5) -> None:
        self.factory = factory
        self.control = DbRunControl(factory, cache_ttl=0)
        self.store: ControlStore = self.control.store
        self.events = EventLog(factory)
        self.audit = AuditRepo(factory)
        self.campaigns = CampaignRepo(factory)
        self.poll_interval_s = poll_interval_s


_plane: ControlPlane | None = None


def get_control_plane() -> ControlPlane:
    global _plane
    if _plane is None:
        settings = get_settings()
        _plane = ControlPlane(make_session_factory(), settings.sse_poll_interval_s)
    return _plane


class KillSwitchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


def _kill_view(plane: ControlPlane) -> dict:
    db_enabled, by, at = plane.store.kill_switch_state()
    env_enabled = env_kill_switch_active()
    return {
        "enabled": db_enabled or env_enabled,
        "env": env_enabled,
        "db": db_enabled,
        "updated_by": by,
        "updated_at": at.isoformat() if at else None,
    }


@router.post("/api/v2/campaigns/{campaign_id}/cancel")
def cancel_campaign(campaign_id: str, plane: ControlPlane = Depends(get_control_plane)):
    """Flag the campaign; the engine stops before its next turn."""
    rec = plane.campaigns.get(campaign_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if rec.status in TERMINAL_CAMPAIGN_STATUSES:
        raise HTTPException(status_code=409, detail=f"Campaign already {rec.status}")
    plane.store.request_cancel(campaign_id, API_ACTOR)
    plane.control.invalidate()
    status = "cancelling"
    if rec.status == "queued":  # never started: nothing to wind down
        plane.campaigns.set_status(campaign_id, "cancelled")
        plane.events.append(
            campaign_id, "campaign_cancelled",
            CampaignCancelledPayload(campaign_id=campaign_id, reason="user", cancelled_by=API_ACTOR),
        )
        status = "cancelled"
    plane.audit.record(API_ACTOR, "campaign.cancel", f"campaign:{campaign_id}", {"was": rec.status})
    logger.info("[API] cancel requested campaign=%s", campaign_id)
    return {"campaign_id": campaign_id, "status": status}


@router.get("/api/v2/admin/kill-switch")
def get_kill_switch(plane: ControlPlane = Depends(get_control_plane)):
    return _kill_view(plane)


@router.post("/api/v2/admin/kill-switch")
def set_kill_switch(body: KillSwitchBody, plane: ControlPlane = Depends(get_control_plane)):
    """Set the global DB kill switch (the env var CANARY_KILL_SWITCH is independent)."""
    plane.store.set_kill_switch(body.enabled, API_ACTOR)
    plane.control.invalidate()
    plane.audit.record(API_ACTOR, "kill_switch.set", "kill_switch", {"enabled": body.enabled})
    if body.enabled:
        get_metrics().alert(
            "Canary kill switch activated",
            "All campaigns will stop before their next turn.",
            level="CRITICAL",
        )
    logger.warning("[API] kill switch set enabled=%s", body.enabled)
    return _kill_view(plane)


@router.get("/api/v2/campaigns/{campaign_id}/events")
async def campaign_events(
    campaign_id: str,
    request: Request,
    last_event_id: Annotated[str | None, Header()] = None,
    plane: ControlPlane = Depends(get_control_plane),
):
    """SSE stream of campaign events. ``Last-Event-ID`` replays events with a larger ``seq``.

    Events come from the persisted log, so a disconnect only ends this
    generator; the run (in a worker process) is unaffected.
    """
    after = 0
    if last_event_id not in (None, ""):
        try:
            after = int(str(last_event_id).strip())
        except ValueError:
            raise HTTPException(status_code=400, detail="Last-Event-ID must be an integer") from None
        if not 0 <= after <= MAX_SEQ:
            raise HTTPException(status_code=400, detail="Last-Event-ID out of range")
    if await run_in_threadpool(plane.campaigns.get, campaign_id) is None:
        raise HTTPException(status_code=404, detail="Campaign not found")

    async def stream():
        last = after
        quiet = 0.0
        while True:
            if await request.is_disconnected():
                return
            rec = await run_in_threadpool(plane.campaigns.get, campaign_id)
            finished = rec is None or rec.status in TERMINAL_CAMPAIGN_STATUSES
            events = await run_in_threadpool(plane.events.since, campaign_id, last)
            for ev in events:
                last = ev.seq
                yield ev.to_sse()
            if events:
                quiet = 0.0
                if any(e.type in TERMINAL_EVENT_TYPES for e in events):
                    return
                continue
            if finished:
                return
            quiet += plane.poll_interval_s
            if quiet >= 15:
                quiet = 0.0
                yield ": keepalive\n\n"
            await asyncio.sleep(plane.poll_interval_s)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
