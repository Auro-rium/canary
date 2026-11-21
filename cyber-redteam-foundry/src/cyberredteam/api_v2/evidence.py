"""/api/v2/conversations and /api/v2/findings (WP8).

Conversations: the transcript is the stored redacted preview by default
(``evidence:read``, viewer+). ``?raw=true`` needs ``evidence:read_raw`` (admin,
or an explicit grant); the org check runs first (404), then the permission
(403), then the read, which writes an ``evidence.read_raw`` audit row. Even raw
transcripts have the target's own credential values masked.

Findings: paged with a total, org-scoped. A lifecycle transition stores the
authenticated principal as reviewer (never a client-supplied id), writes a
``finding_events`` row and an audit row, and sends the decision to Weave as
human-triage feedback (WP11 ``log_human_triage``; a no-op without Weave).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.api_v2.schemas import (
    ConversationDetail,
    FindingDetail,
    FindingEventView,
    FindingPage,
    FindingStatus,
    FindingTransition,
    FindingView,
)
from cyberredteam.api_v2.scope import conversation_in_org, finding_in_org
from cyberredteam.auth.deps import get_db_factory, require
from cyberredteam.auth.principal import (
    EVIDENCE_READ,
    EVIDENCE_READ_RAW,
    FINDINGS_READ,
    FINDINGS_TRIAGE,
    Principal,
)
from cyberredteam.jobs.events import scrub_secrets
from cyberredteam.jobs.runner_wiring import auth_secret_values
from cyberredteam.observability.weave_tracing import log_human_triage
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.redaction import redact
from cyberredteam.storage.v2.repositories import (
    TERMINAL_FINDING_STATUSES,
    ConversationRepo,
    FindingRepo,
    InvalidTransition,
    SqlTargetStore,
    VerdictRepo,
)

logger = logging.getLogger(__name__)

conversations = APIRouter(prefix="/api/v2/conversations", tags=["evidence"])
findings = APIRouter(prefix="/api/v2/findings", tags=["findings"])

def target_secret_values(factory: sessionmaker[Session], target_id: str | None) -> tuple[str, ...]:
    """The target's own credential values, masked in every response (raw or not):
    a target that echoes its key must not leak it through the API."""
    target = SqlTargetStore(factory).get(target_id) if target_id else None
    return auth_secret_values(target) if target else ()


def _conversation_target(factory: sessionmaker[Session], conversation_id: str) -> str | None:
    with session_scope(factory) as s:
        return s.scalar(
            select(orm.CampaignRow.target_id)
            .join(orm.ConversationRow, orm.ConversationRow.campaign_id == orm.CampaignRow.campaign_id)
            .where(orm.ConversationRow.conversation_id == conversation_id)
        )


@conversations.get("/{conversation_id}", response_model=ConversationDetail)
def get_conversation(
    conversation_id: str,
    raw: bool = False,
    principal: Principal = Depends(require(EVIDENCE_READ)),
    factory: sessionmaker[Session] = Depends(get_db_factory),
):
    if not conversation_in_org(factory, conversation_id, principal.org_id):
        raise HTTPException(status_code=404, detail="Conversation not found")
    if raw and not principal.can(EVIDENCE_READ_RAW):
        raise HTTPException(status_code=403, detail=f"Requires permission {EVIDENCE_READ_RAW}")
    actor = principal.actor if raw else None
    conv = ConversationRepo(factory).get(conversation_id, raw=raw, actor=actor)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    verdict = VerdictRepo(factory).get(conversation_id, raw=raw, actor=actor)
    secrets = target_secret_values(factory, _conversation_target(factory, conversation_id))
    if not raw:
        conv = conv.model_copy(update={"target_session_ref": None})
    conv = type(conv).model_validate(scrub_secrets(conv.model_dump(mode="json"), secrets))
    if verdict is not None:
        verdict = type(verdict).model_validate(scrub_secrets(verdict.model_dump(mode="json"), secrets))
    if raw:
        logger.info("[API] raw evidence read conversation=%s by %s", conversation_id, actor)
    return ConversationDetail(conversation=conv, verdict=verdict, raw=raw)


# ── Findings ─────────────────────────────────────────────────────────────────


def _finding_views(
    s: Session, rows: list[orm.FindingRow], factory: sessionmaker[Session]
) -> list[FindingView]:
    conv_ids = [r.conversation_id for r in rows if r.conversation_id]
    verdicts: dict[str, orm.VerdictRow] = {}
    if conv_ids:
        verdicts = {
            v.conversation_id: v
            for v in s.scalars(select(orm.VerdictRow).where(orm.VerdictRow.conversation_id.in_(conv_ids)))
        }
    ids = [r.finding_id for r in rows]
    reviewers: dict[str, str | None] = {}
    if ids:
        events = s.scalars(
            select(orm.FindingEventRow)
            .where(orm.FindingEventRow.finding_id.in_(ids),
                   orm.FindingEventRow.reviewer_id.is_not(None),
                   orm.FindingEventRow.reviewer_id != "system")
            .order_by(orm.FindingEventRow.id)
        )
        for e in events:
            reviewers[e.finding_id] = e.reviewer_id
    out = []
    secrets: dict[str, tuple[str, ...]] = {}
    for r in rows:
        if r.target_id not in secrets:
            secrets[r.target_id] = target_secret_values(factory, r.target_id)
        v = verdicts.get(r.conversation_id or "")
        out.append(
            FindingView(
                finding_id=r.finding_id, target_id=r.target_id,
                campaign_id=r.last_seen_campaign or r.first_seen_campaign,
                conversation_id=r.conversation_id, technique=r.technique,
                asi_class=r.asi_class, severity=r.severity, status=r.status, title=r.title,
                seen_in_campaigns=list(r.seen_in_campaigns or []),
                first_failing_turn=v.first_failing_turn if v else None,
                rationale=scrub_secrets(redact(v.rationale).text, secrets[r.target_id])
                if v and v.rationale else "",
                reviewer_id=reviewers.get(r.finding_id),
                created_at=r.created_at, updated_at=r.updated_at,
            )
        )
    return out


def _finding_detail(factory: sessionmaker[Session], finding_id: str) -> FindingDetail:
    with session_scope(factory) as s:
        row = s.get(orm.FindingRow, finding_id)
        view = _finding_views(s, [row], factory)[0]
    events = [
        FindingEventView(from_status=e.from_status, to_status=e.to_status,
                         reviewer_id=e.reviewer_id, rationale=e.rationale, at=e.at)
        for e in FindingRepo(factory).events(finding_id)
    ]
    return FindingDetail(**view.model_dump(), events=events)


@findings.get("", response_model=FindingPage)
def list_findings(
    principal: Principal = Depends(require(FINDINGS_READ)),
    factory: sessionmaker[Session] = Depends(get_db_factory),
    target_id: str | None = None,
    campaign_id: str | None = None,
    status: FindingStatus | None = None,
    severity: str | None = None,
    asi_class: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with session_scope(factory) as s:
        q = (
            select(orm.FindingRow)
            .join(orm.TargetRow, orm.TargetRow.target_id == orm.FindingRow.target_id)
            .where(orm.TargetRow.org_id == principal.org_id)
        )
        if target_id:
            q = q.where(orm.FindingRow.target_id == target_id)
        if campaign_id:
            q = q.where(
                (orm.FindingRow.last_seen_campaign == campaign_id)
                | (orm.FindingRow.first_seen_campaign == campaign_id)
            )
        if status:
            q = q.where(orm.FindingRow.status == status)
        if severity:
            q = q.where(orm.FindingRow.severity == severity.lower())
        if asi_class:
            q = q.where(orm.FindingRow.asi_class == asi_class.upper().replace("-", ""))
        total = s.scalar(select(func.count()).select_from(q.subquery())) or 0
        rows = list(
            s.scalars(
                q.order_by(orm.FindingRow.created_at.desc(), orm.FindingRow.finding_id)
                .offset((page - 1) * page_size).limit(page_size)
            )
        )
        items = _finding_views(s, rows, factory)
    return FindingPage(items=items, total=int(total), page=page, page_size=page_size)


@findings.get("/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: str,
    principal: Principal = Depends(require(FINDINGS_READ)),
    factory: sessionmaker[Session] = Depends(get_db_factory),
):
    if not finding_in_org(factory, finding_id, principal.org_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_detail(factory, finding_id)


@findings.put("/{finding_id}/status", response_model=FindingDetail)
def transition_finding(
    finding_id: str,
    body: FindingTransition,
    principal: Principal = Depends(require(FINDINGS_TRIAGE)),
    factory: sessionmaker[Session] = Depends(get_db_factory),
):
    """Move a finding along its lifecycle; the reviewer is the caller. 409 on an
    illegal transition; closing statuses need a rationale (422)."""
    if not finding_in_org(factory, finding_id, principal.org_id):
        raise HTTPException(status_code=404, detail="Finding not found")
    rationale = (body.rationale or "").strip() or None
    if body.status in TERMINAL_FINDING_STATUSES and not rationale:
        raise HTTPException(status_code=422, detail=f"{body.status} requires a rationale")
    repo = FindingRepo(factory)
    try:
        record = repo.transition(finding_id, body.status, reviewer_id=principal.actor,
                                 rationale=rationale)
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    judge = None
    if record.conversation_id:
        with session_scope(factory) as s:
            judge = s.scalar(
                select(orm.VerdictRow.verdict).where(
                    orm.VerdictRow.conversation_id == record.conversation_id
                )
            )
    log_human_triage(None, finding_id=finding_id, decision=body.status,
                     reviewer=principal.actor, judge_verdict=judge)
    return _finding_detail(factory, finding_id)
