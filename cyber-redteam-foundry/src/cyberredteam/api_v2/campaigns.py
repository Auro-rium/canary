"""/api/v2/campaigns: create, list, get (WP8). Cancel and SSE events live in
``jobs/api_v2.py`` (WP7) and carry the same authz.

Create is the launch gate:

1. ``campaigns:launch`` (operator+), else 403.
2. Target in the caller's org and not archived, else 404.
3. Target ownership-verified, else 403.
4. ``ALLOWED_TARGETS`` (if set) narrows further, else 403.
5. ``CampaignRequest(target, policy)`` validation: production limits
   (rps<=1, parallel<=2, total<=300, no destructive tools) are rejected, never
   clamped (422), then WP3 ``normalize_request`` (422 on ``CampaignRefused``).
   The worker re-runs both checks at load time and the engine at start.
6. Global kill switch on: 409.
7. Store, audit, enqueue. If the enqueue fails the campaign is marked failed (503).
"""

from __future__ import annotations

import logging
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.api_v2.deps import get_job_queue, get_target_store
from cyberredteam.api_v2.schemas import (
    BudgetState,
    CampaignCreate,
    CampaignDetail,
    CampaignPage,
    CampaignSummary,
    ConversationSummary,
)
from cyberredteam.auth.deps import get_db_factory, require
from cyberredteam.auth.principal import CAMPAIGNS_LAUNCH, CAMPAIGNS_READ, Principal
from cyberredteam.contracts import CampaignPolicy, CampaignRequest
from cyberredteam.engine.runner import CampaignRefused, normalize_request
from cyberredteam.jobs.control import ControlStore, env_kill_switch_active
from cyberredteam.jobs.queue import JobQueue
from cyberredteam.jobs.tables import CampaignEventRow
from cyberredteam.settings import get_settings
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.repositories import (
    AuditRepo,
    BudgetLedgerRepo,
    CampaignRepo,
    SqlTargetStore,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v2/campaigns", tags=["campaigns"])


def _allowlist() -> list[str]:
    return [t.strip() for t in get_settings().allowed_targets.split(",") if t.strip()]


def _summaries(s: Session, rows: list[tuple[orm.CampaignRow, orm.TargetRow]]) -> list[CampaignSummary]:
    ids = [c.campaign_id for c, _ in rows]
    totals: dict[str, int] = {}
    confirmed: dict[str, int] = {}
    if ids:
        totals = dict(
            s.execute(
                select(orm.ConversationRow.campaign_id, func.count())
                .where(orm.ConversationRow.campaign_id.in_(ids))
                .group_by(orm.ConversationRow.campaign_id)
            ).all()
        )
        confirmed = dict(
            s.execute(
                select(orm.ConversationRow.campaign_id, func.count())
                .join(orm.VerdictRow,
                      orm.VerdictRow.conversation_id == orm.ConversationRow.conversation_id)
                .where(orm.ConversationRow.campaign_id.in_(ids),
                       orm.VerdictRow.verdict == "confirmed")
                .group_by(orm.ConversationRow.campaign_id)
            ).all()
        )
    return [
        CampaignSummary(
            campaign_id=c.campaign_id, target_id=c.target_id, target_name=t.name,
            environment=t.environment, status=c.status, created_by=c.created_by,
            created_at=c.created_at, finished_at=c.finished_at,
            total_conversations=int(totals.get(c.campaign_id, 0)),
            confirmed=int(confirmed.get(c.campaign_id, 0)),
        )
        for c, t in rows
    ]


def _scoped(org_id: str):
    return (
        select(orm.CampaignRow, orm.TargetRow)
        .join(orm.TargetRow, orm.TargetRow.target_id == orm.CampaignRow.target_id)
        .where(orm.TargetRow.org_id == org_id)
    )


def campaign_detail(factory: sessionmaker[Session], campaign_id: str, org_id: str) -> CampaignDetail | None:
    with session_scope(factory) as s:
        row = s.execute(_scoped(org_id).where(orm.CampaignRow.campaign_id == campaign_id)).first()
        if row is None:
            return None
        campaign, _target = row
        summary = _summaries(s, [tuple(row)])[0]
        policy = CampaignPolicy.model_validate(campaign.policy)
        turns = dict(
            s.execute(
                select(orm.TurnRow.conversation_id, func.count())
                .join(orm.ConversationRow,
                      orm.ConversationRow.conversation_id == orm.TurnRow.conversation_id)
                .where(orm.ConversationRow.campaign_id == campaign_id)
                .group_by(orm.TurnRow.conversation_id)
            ).all()
        )
        convs = s.execute(
            select(orm.ConversationRow, orm.VerdictRow.verdict)
            .outerjoin(orm.VerdictRow,
                       orm.VerdictRow.conversation_id == orm.ConversationRow.conversation_id)
            .where(orm.ConversationRow.campaign_id == campaign_id)
            .order_by(orm.ConversationRow.technique, orm.ConversationRow.trial_index)
        ).all()
        last_seq = s.scalar(
            select(func.coalesce(func.max(CampaignEventRow.seq), 0)).where(
                CampaignEventRow.campaign_id == campaign_id
            )
        )
        conversations = [
            ConversationSummary(
                conversation_id=c.conversation_id, technique=c.technique,
                trial_index=c.trial_index, status=c.status,
                turns=int(turns.get(c.conversation_id, 0)), verdict=v,
            )
            for c, v in convs
        ]
    totals = BudgetLedgerRepo(factory).totals(campaign_id)
    return CampaignDetail(
        **summary.model_dump(),
        policy=policy,
        conversations=conversations,
        technique_results=CampaignRepo(factory).technique_results(campaign_id),
        budget=BudgetState(
            requests_used=totals["requests"], max_total_requests=policy.max_total_requests,
            llm_cost_usd=totals["usd"], max_llm_cost_usd=policy.max_llm_cost_usd,
        ),
        last_seq=int(last_seq or 0),
    )


@router.post("", status_code=201, response_model=CampaignDetail)
async def create_campaign(
    body: CampaignCreate,
    principal: Principal = Depends(require(CAMPAIGNS_LAUNCH)),
    store: SqlTargetStore = Depends(get_target_store),
    factory: sessionmaker[Session] = Depends(get_db_factory),
    queue: JobQueue = Depends(get_job_queue),
):
    try:
        target = store.get_in_org(body.target_id, principal.org_id)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Target store is unavailable.") from None
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if target.verified is not True:
        raise HTTPException(
            status_code=403,
            detail="Target is not ownership-verified. Verify it with "
                   "POST /api/v2/targets/{id}/verify first.",
        )
    allowed = _allowlist()
    if allowed and target.target_id not in allowed and str(target.endpoint) not in allowed:
        raise HTTPException(status_code=403, detail="Target is not in the authorized allowlist.")
    try:
        request = CampaignRequest(target=target, policy=body.policy)
        normalize_request(request)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(include_input=False, include_url=False, include_context=False),
        ) from None
    except CampaignRefused as exc:
        raise HTTPException(status_code=422, detail=f"campaign refused: {exc}") from None
    if env_kill_switch_active() or ControlStore(factory).kill_switch_state()[0]:
        raise HTTPException(status_code=409, detail="The global kill switch is on; no launches.")

    campaign_id = f"c-{uuid.uuid4().hex}"
    repo = CampaignRepo(factory)
    repo.create(campaign_id, target.target_id, body.policy, created_by=principal.actor)
    audit = AuditRepo(factory)
    audit.record(principal.actor, "campaign.create", f"campaign:{campaign_id}",
                 {"target_id": target.target_id, "environment": target.environment})
    try:
        await queue.enqueue_campaign(campaign_id)
    except Exception as exc:
        repo.set_status(campaign_id, "failed")
        audit.record(principal.actor, "campaign.enqueue_failed", f"campaign:{campaign_id}",
                     {"error": type(exc).__name__})
        logger.error("[API] enqueue failed campaign=%s (%s)", campaign_id, type(exc).__name__)
        raise HTTPException(status_code=503, detail="Job queue unavailable; campaign not started.") from None
    logger.info("[API] campaign %s queued by %s", campaign_id, principal.actor)
    return campaign_detail(factory, campaign_id, principal.org_id)


@router.get("", response_model=CampaignPage)
def list_campaigns(
    principal: Principal = Depends(require(CAMPAIGNS_READ)),
    factory: sessionmaker[Session] = Depends(get_db_factory),
    target_id: str | None = None,
    status: Literal["queued", "running", "completed", "failed", "cancelled"] | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
):
    with session_scope(factory) as s:
        q = _scoped(principal.org_id)
        if target_id:
            q = q.where(orm.CampaignRow.target_id == target_id)
        if status:
            q = q.where(orm.CampaignRow.status == status)
        total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
        rows = s.execute(
            q.order_by(orm.CampaignRow.created_at.desc(), orm.CampaignRow.campaign_id)
            .offset((page - 1) * page_size).limit(page_size)
        ).all()
        items = _summaries(s, [tuple(r) for r in rows])
    return CampaignPage(items=items, total=int(total), page=page, page_size=page_size)


@router.get("/{campaign_id}", response_model=CampaignDetail)
def get_campaign(
    campaign_id: str,
    principal: Principal = Depends(require(CAMPAIGNS_READ)),
    factory: sessionmaker[Session] = Depends(get_db_factory),
):
    detail = campaign_detail(factory, campaign_id, principal.org_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return detail
