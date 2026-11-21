"""/api/v2/reports/{campaign_id}: JSON, Markdown and PDF (WP8).

``reports:read`` (viewer+), org-scoped. Reports are built only from redacted
data (technique results, redacted verdict rationales, findings); they never
contain raw evidence, target credentials or the webhook.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cyberredteam.api_v2.campaigns import campaign_detail
from cyberredteam.api_v2.evidence import target_secret_values
from cyberredteam.api_v2.pdf import render_text_pdf
from cyberredteam.auth.deps import get_db_factory, require
from cyberredteam.auth.principal import REPORTS_READ, Principal
from cyberredteam.jobs.events import scrub_secrets
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import session_scope
from cyberredteam.storage.v2.redaction import redact

router = APIRouter(prefix="/api/v2/reports", tags=["reports"])

_RATIONALE_CAP = 500


def build_report(factory: sessionmaker[Session], campaign_id: str, principal: Principal) -> dict[str, Any] | None:
    detail = campaign_detail(factory, campaign_id, principal.org_id)
    if detail is None:
        return None
    with session_scope(factory) as s:
        rows = s.execute(
            select(orm.ConversationRow, orm.VerdictRow)
            .outerjoin(orm.VerdictRow,
                       orm.VerdictRow.conversation_id == orm.ConversationRow.conversation_id)
            .where(orm.ConversationRow.campaign_id == campaign_id)
            .order_by(orm.ConversationRow.technique, orm.ConversationRow.trial_index)
        ).all()
        conversations = [
            {
                "conversation_id": c.conversation_id,
                "technique": c.technique,
                "trial_index": c.trial_index,
                "status": c.status,
                "verdict": v.verdict if v else None,
                "severity": v.severity if v else None,
                "asi_class": v.asi_class if v else None,
                "first_failing_turn": v.first_failing_turn if v else None,
                "judge_agreement": v.judge_agreement if v else None,
                "rationale": redact(v.rationale or "").text[:_RATIONALE_CAP] if v else "",
            }
            for c, v in rows
        ]
        finding_rows = s.scalars(
            select(orm.FindingRow)
            .where((orm.FindingRow.last_seen_campaign == campaign_id)
                   | (orm.FindingRow.first_seen_campaign == campaign_id))
            .order_by(orm.FindingRow.created_at)
        ).all()
        findings = [
            {
                "finding_id": f.finding_id, "technique": f.technique, "asi_class": f.asi_class,
                "severity": f.severity, "status": f.status, "title": redact(f.title or "").text,
                "conversation_id": f.conversation_id,
            }
            for f in finding_rows
        ]
    secrets = target_secret_values(factory, detail.target_id)
    conversations = scrub_secrets(conversations, secrets)
    findings = scrub_secrets(findings, secrets)
    counts: dict[str, int] = {}
    for c in conversations:
        key = c["verdict"] or "none"
        counts[key] = counts.get(key, 0) + 1
    return {
        "report_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": principal.actor,
        "campaign": {
            "campaign_id": detail.campaign_id, "status": detail.status,
            "created_by": detail.created_by,
            "created_at": detail.created_at.isoformat() if detail.created_at else None,
            "finished_at": detail.finished_at.isoformat() if detail.finished_at else None,
            "policy": detail.policy.model_dump(mode="json"),
            "budget": detail.budget.model_dump(mode="json"),
        },
        "target": {
            "target_id": detail.target_id, "name": detail.target_name,
            "environment": detail.environment,
        },
        "summary": {
            "conversations": detail.total_conversations,
            "confirmed": detail.confirmed,
            "verdicts": counts,
        },
        "technique_results": [t.model_dump(mode="json") for t in detail.technique_results],
        "conversations": conversations,
        "findings": findings,
    }


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    c, t, sm = report["campaign"], report["target"], report["summary"]
    lines = [
        f"# Canary campaign report: {_cell(c['campaign_id'])}",
        "",
        f"- Target: {_cell(t['name'])} (`{_cell(t['target_id'])}`, {t['environment']})",
        f"- Status: {c['status']}",
        f"- Created: {c['created_at'] or '-'} by {_cell(c['created_by'] or '-')}",
        f"- Finished: {c['finished_at'] or '-'}",
        f"- Conversations: {sm['conversations']}, confirmed: {sm['confirmed']}",
        f"- Generated: {report['generated_at']} by {_cell(report['generated_by'])}",
        "",
        "Evidence in this report is redacted. Raw transcripts are available only "
        "through the audited raw-evidence API.",
        "",
        "## Results by technique",
        "",
        "| Technique | Trials | Confirmed | Success rate | 95% CI |",
        "|---|---|---|---|---|",
    ]
    for r in report["technique_results"]:
        lines.append(
            f"| {_cell(r['technique'])} | {r['trials']} | {r['confirmed']} | "
            f"{r['success_rate']:.2f} | {r['ci95_low']:.2f}-{r['ci95_high']:.2f} |"
        )
    if not report["technique_results"]:
        lines.append("| (no results yet) | | | | |")
    lines += ["", "## Conversations", "",
              "| Conversation | Technique | Trial | Status | Verdict | Severity | ASI | First failing turn |",
              "|---|---|---|---|---|---|---|---|"]
    for cv in report["conversations"]:
        lines.append(
            f"| {_cell(cv['conversation_id'])} | {_cell(cv['technique'])} | {cv['trial_index']} | "
            f"{cv['status']} | {cv['verdict'] or '-'} | {cv['severity'] or '-'} | "
            f"{cv['asi_class'] or '-'} | {'-' if cv['first_failing_turn'] is None else cv['first_failing_turn']} |"
        )
    confirmed = [cv for cv in report["conversations"] if cv["verdict"] == "confirmed"]
    if confirmed:
        lines += ["", "## Confirmed conversations", ""]
        for cv in confirmed:
            lines.append(f"### {_cell(cv['conversation_id'])} ({_cell(cv['technique'])})")
            lines += ["", _cell(cv["rationale"]) or "(no rationale)", ""]
    lines += ["", "## Findings", "", "| Finding | Severity | ASI | Status | Title |", "|---|---|---|---|---|"]
    for f in report["findings"]:
        lines.append(
            f"| {_cell(f['finding_id'])} | {f['severity']} | {f['asi_class']} | {f['status']} | "
            f"{_cell(f['title'])} |"
        )
    if not report["findings"]:
        lines.append("| (none) | | | | |")
    return "\n".join(lines) + "\n"


@router.get(
    "/{campaign_id}",
    responses={
        200: {
            "description": "The report",
            "content": {
                "application/json": {},
                "text/markdown": {"schema": {"type": "string"}},
                "application/pdf": {"schema": {"type": "string", "format": "binary"}},
            },
        }
    },
)
def get_report(
    campaign_id: str,
    format: Literal["json", "md", "pdf"] = "json",
    principal: Principal = Depends(require(REPORTS_READ)),
    factory: sessionmaker[Session] = Depends(get_db_factory),
):
    report = build_report(factory, campaign_id, principal)
    if report is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    filename = f"canary-report-{campaign_id}"
    if format == "json":
        return JSONResponse(report)
    markdown = render_markdown(report)
    if format == "md":
        return Response(
            markdown, media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}.md"'},
        )
    return Response(
        render_text_pdf(markdown, title=f"Canary report {campaign_id}"),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'},
    )
