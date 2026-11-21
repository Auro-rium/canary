"""API v2 control-plane routes (WP7): cancel, kill switch, SSE events with resume.

Authz (WP8): cancel needs ``campaigns:cancel`` (operator+), events
``campaigns:read`` (viewer+), kill-switch GET ``kill_switch:read`` (everyone),
POST ``kill_switch:write`` (admin who is also a platform admin). Campaigns are org-scoped: another org's
campaign is a 404. Audit rows carry the authenticated principal.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.api_v2.schemas import CancelResult, KillSwitchBody, KillSwitchState
from cyberredteam.api_v2.scope import campaign_in_org
from cyberredteam.auth.deps import get_db_factory, require
from cyberredteam.auth.principal import (
    CAMPAIGNS_CANCEL,
    CAMPAIGNS_READ,
    KILL_SWITCH_READ,
    KILL_SWITCH_WRITE,
    Principal,
    is_platform_admin,
)
from cyberredteam.auth.repo import AuthRepo
from cyberredteam.contracts import CampaignCancelledPayload
from cyberredteam.jobs.control import ControlStore, DbRunControl, env_kill_switch_active
from cyberredteam.jobs.events import MAX_SEQ, TERMINAL_EVENT_TYPES, EventLog
from cyberredteam.observability.hooks import get_metrics
from cyberredteam.settings import get_settings
from cyberredteam.storage.v2.repositories import (
    TERMINAL_CAMPAIGN_STATUSES,
    AuditRepo,
    CampaignRepo,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["control"])

# How often a long-lived SSE stream re-checks that its session/API key is still valid.
REVALIDATE_S = 30.0


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


def get_control_plane(factory: sessionmaker[Session] = Depends(get_db_factory)) -> ControlPlane:
    return ControlPlane(factory, get_settings().sse_poll_interval_s)


def _kill_view(plane: ControlPlane) -> KillSwitchState:
    db_enabled, by, at = plane.store.kill_switch_state()
    env_enabled = env_kill_switch_active()
    return KillSwitchState(
        enabled=db_enabled or env_enabled,
        active=db_enabled or env_enabled,
        env=env_enabled,
        db=db_enabled,
        updated_by=by,
        updated_at=at.isoformat() if at else None,
    )


@router.post("/api/v2/campaigns/{campaign_id}/cancel", response_model=CancelResult)
def cancel_campaign(
    campaign_id: str,
    principal: Principal = Depends(require(CAMPAIGNS_CANCEL)),
    plane: ControlPlane = Depends(get_control_plane),
):
    """Flag the campaign; the engine stops before its next turn."""
    rec = plane.campaigns.get(campaign_id)
    if rec is None or not campaign_in_org(plane.factory, campaign_id, principal.org_id):
        raise HTTPException(status_code=404, detail="Campaign not found")
    if rec.status in TERMINAL_CAMPAIGN_STATUSES:
        raise HTTPException(status_code=409, detail=f"Campaign already {rec.status}")
    actor = principal.actor
    plane.store.request_cancel(campaign_id, actor)
    plane.control.invalidate()
    status = "cancelling"
    if rec.status == "queued":  # never started: nothing to wind down
        plane.campaigns.set_status(campaign_id, "cancelled")
        plane.events.append(
            campaign_id, "campaign_cancelled",
            CampaignCancelledPayload(campaign_id=campaign_id, reason="user", cancelled_by=actor),
        )
        status = "cancelled"
    plane.audit.record(actor, "campaign.cancel", f"campaign:{campaign_id}", {"was": rec.status})
    logger.info("[API] cancel requested campaign=%s", campaign_id)
    return {"campaign_id": campaign_id, "status": status}


@router.get("/api/v2/admin/kill-switch", response_model=KillSwitchState)
def get_kill_switch(
    principal: Principal = Depends(require(KILL_SWITCH_READ)),
    plane: ControlPlane = Depends(get_control_plane),
):
    """Kill-switch status; every signed-in role may read it."""
    return _kill_view(plane)


@router.post("/api/v2/admin/kill-switch", response_model=KillSwitchState)
def set_kill_switch(
    body: KillSwitchBody,
    principal: Principal = Depends(require(KILL_SWITCH_WRITE)),
    plane: ControlPlane = Depends(get_control_plane),
):
    """Set the global DB kill switch (platform admins only: ``CANARY_PLATFORM_ADMINS``).
    It halts every org's campaigns, so an org admin cannot flip it. The env var CANARY_KILL_SWITCH is independent."""
    if not is_platform_admin(principal):
        raise HTTPException(status_code=403, detail="The global kill switch needs a platform admin")
    actor = principal.actor
    plane.store.set_kill_switch(body.enabled, actor)
    plane.control.invalidate()
    plane.audit.record(actor, "kill_switch.set", "kill_switch",
                       {"enabled": body.enabled, "reason": body.reason, "org_id": principal.org_id})
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
    principal: Principal = Depends(require(CAMPAIGNS_READ)),
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
    if not await run_in_threadpool(campaign_in_org, plane.factory, campaign_id, principal.org_id):
        raise HTTPException(status_code=404, detail="Campaign not found")

    auth_repo = AuthRepo(plane.factory)

    async def stream():
        last = after
        quiet = 0.0
        next_check = time.monotonic() + REVALIDATE_S
        while True:
            if await request.is_disconnected():
                return
            if time.monotonic() >= next_check:
                next_check = time.monotonic() + REVALIDATE_S
                if not await run_in_threadpool(auth_repo.is_still_valid, principal):
                    yield "event: error\ndata: {\"detail\": \"session ended\"}\n\n"
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
