"""FastAPI app: API v2 (WP8 auth, org-scoped) plus the deprecated v1 read routes.

Auth is enforced app-wide by ``auth.deps.require_auth``: every route needs an
OIDC browser session or a per-user API key, except the public health and login
routes. There is no shared master token. Roles and org isolation are enforced
per route (see ``auth/principal.py`` and the v2 routers).

v1: only the read routes remain, behind ``V1_API_ENABLED`` (default on for one
release), admin-only (legacy data has no org), with ``Deprecation``/``Sunset``
headers. ``POST /api/runs``, the old SSE ``POST /api/campaigns/run`` and the v1
finding status write were removed in WP8; use /api/v2.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select

from cyberredteam.api_v2.deps import (  # noqa: F401 (re-export)
    get_ownership_options,
    get_target_store,
)
from cyberredteam.auth.deps import get_principal, require_auth
from cyberredteam.auth.principal import LEGACY_READ, Principal
from cyberredteam.logging import setup_logging
from cyberredteam.settings import get_settings
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import AttackRecord, FindingRecord, LLMCallRecord, RunRecord

logger = logging.getLogger("cyberredteam.api")
logging.basicConfig(level=logging.INFO)

settings = get_settings()
setup_logging(settings.log_level, settings.log_file)

def _authorized_targets() -> list[str]:
    return [t.strip() for t in settings.allowed_targets.split(",") if t.strip()]


# Auth is enforced on every route via the app-level dependency (public paths
# are allowlisted in auth.deps).
app = FastAPI(
    title="Canary API",
    version="2.0.0",
    dependencies=[Depends(require_auth)],
)

# The browser reaches the API through the same-origin proxy with cookies, so no
# cross-origin credentials are allowed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def unauthenticated_health_check(request, call_next):
    """Expose a minimal container/load-balancer probe without API credentials."""
    if request.url.path == "/health":
        return JSONResponse({"status": "ok"})
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_error_without_input(request: Request, exc: RequestValidationError):
    """422 that never echoes submitted values (bodies may carry target secrets)."""
    errors = [
        {"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")}
        for e in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


def require_v1(response: Response, principal: Principal = Depends(get_principal)) -> Principal:
    """Deprecated v1 read routes: feature flag, admin-only, deprecation headers."""
    if not settings.v1_api_enabled:
        raise HTTPException(status_code=410, detail="The v1 API has been removed; use /api/v2.")
    if not principal.can(LEGACY_READ):
        raise HTTPException(status_code=403, detail=f"Requires permission {LEGACY_READ}")
    response.headers["Deprecation"] = "true"
    response.headers["Sunset"] = settings.v1_sunset
    response.headers["Link"] = '</api/v2>; rel="successor-version"'
    return principal


v1 = APIRouter(dependencies=[Depends(require_v1)], include_in_schema=False)


def _running_count() -> int:
    """Count running legacy runs from SQLite."""
    try:
        store = SQLiteStore(Path(settings.db_path))
        with store.SessionLocal() as session:
            count = len(session.scalars(select(RunRecord).where(RunRecord.status == "running")).all())
        store.close()
        return count
    except Exception as exc:
        logger.warning("Could not read persisted run count: %s", exc)
        return 0


@app.on_event("startup")
def start_observability() -> None:
    from cyberredteam.observability.setup import init_observability

    init_observability(settings, service_name="api")


@app.on_event("shutdown")
def stop_observability() -> None:
    from cyberredteam.observability.setup import shutdown_observability

    shutdown_observability()


@app.on_event("startup")
def recover_interrupted_runs() -> None:
    """Mark runs interrupted by an API restart instead of leaving them hanging."""
    store = SQLiteStore(Path(settings.db_path))
    with store.SessionLocal() as session:
        stale = session.scalars(select(RunRecord).where(RunRecord.status == "running")).all()
        for run in stale:
            run.status = "failed"
            run.error = "API process restarted while this run was active."
            run.end_time = datetime.utcnow()
        if stale:
            session.commit()
            logger.warning("Marked %d interrupted run(s) as failed after restart", len(stale))
    store.close()


@v1.get("/api/status")
def get_status():
    """Verify backend status."""
    db_exists = Path(settings.db_path).exists()
    return {
        "status": "healthy",
        "database": str(settings.db_path),
        "database_exists": db_exists,
        "report_directory": str(settings.report_output_dir),
        "active_runs": _running_count(),
        "target_allowlist_configured": bool(_authorized_targets()),
        "log_file": str(settings.log_file),
    }


def _llm_stats_by_run(session, run_ids: List[str]) -> Dict[str, Dict[str, int | float]]:
    """Return compact, run-linked LLM telemetry for list/dashboard responses."""
    if not run_ids:
        return {}
    rows = session.execute(
        select(
            LLMCallRecord.run_id,
            func.count(LLMCallRecord.id),
            func.coalesce(func.sum(LLMCallRecord.prompt_tokens), 0),
            func.coalesce(func.sum(LLMCallRecord.completion_tokens), 0),
            func.coalesce(func.sum(LLMCallRecord.latency), 0),
        )
        .where(LLMCallRecord.run_id.in_(run_ids))
        .group_by(LLMCallRecord.run_id)
    ).all()
    return {
        run_id: {
            "calls": int(calls),
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            "total_tokens": int(prompt_tokens) + int(completion_tokens),
            "latency_ms": round(float(latency or 0) * 1000, 2),
        }
        for run_id, calls, prompt_tokens, completion_tokens, latency in rows
        if run_id
    }


def _run_summary(run: RunRecord, llm_stats: Optional[Dict[str, int | float]] = None) -> Dict:
    """Serialize a run without raw prompts/responses for campaign lists."""
    return {
        "run_id": run.run_id,
        "target_id": run.target_id,
        "status": run.status,
        "error": run.error,
        "start_time": run.start_time.isoformat() if run.start_time else None,
        "end_time": run.end_time.isoformat() if run.end_time else None,
        "total_attacks": run.total_attacks or 0,
        "successful_attacks": run.successful_attacks or 0,
        "success_rate": run.success_rate or 0.0,
        "llm_stats": llm_stats or {
            "calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "latency_ms": 0.0,
        },
    }


@v1.get("/api/dashboard/overview")
def get_dashboard_overview():
    """Return truthful aggregate metrics for the operations-console landing page."""
    store = SQLiteStore(Path(settings.db_path))
    with store.SessionLocal() as session:
        runs = list(session.scalars(select(RunRecord)).all())
        findings = list(session.scalars(select(FindingRecord)).all())
        llm = session.execute(
            select(
                func.count(LLMCallRecord.id),
                func.coalesce(func.sum(LLMCallRecord.prompt_tokens), 0),
                func.coalesce(func.sum(LLMCallRecord.completion_tokens), 0),
                func.coalesce(func.sum(LLMCallRecord.latency), 0),
            )
        ).one()
    store.close()

    by_status: Dict[str, int] = {}
    for run in runs:
        by_status[run.status] = by_status.get(run.status, 0) + 1
    open_findings = [finding for finding in findings if finding.status == "open"]
    severity_counts: Dict[str, int] = {}
    for finding in open_findings:
        severity = (finding.severity or "info").lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    calls, prompt_tokens, completion_tokens, latency = llm
    return {
        "backend": {
            "status": "healthy",
            "active_runs": _running_count(),
            "target_allowlist_configured": bool(_authorized_targets()),
        },
        "campaigns": {
            "total": len(runs),
            "by_status": by_status,
            "targets": len({run.target_id for run in runs if run.target_id}),
        },
        "open_findings": {
            "total": len(open_findings),
            "by_severity": severity_counts,
        },
        "llm_stats": {
            "calls": int(calls),
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            "total_tokens": int(prompt_tokens) + int(completion_tokens),
            "latency_ms": round(float(latency or 0) * 1000, 2),
        },
    }


@v1.get("/api/runs")
def list_runs(
    target_id: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 25,
):
    """Paginated campaign history for the dashboard; raw evidence stays on run detail."""
    if page < 1 or page_size < 1 or page_size > 100:
        raise HTTPException(status_code=422, detail="page must be >= 1 and page_size must be 1-100")

    store = SQLiteStore(Path(settings.db_path))
    with store.SessionLocal() as session:
        query = select(RunRecord)
        count_query = select(func.count(RunRecord.run_id))
        if target_id:
            query = query.where(RunRecord.target_id == target_id)
            count_query = count_query.where(RunRecord.target_id == target_id)
        if status:
            query = query.where(RunRecord.status == status)
            count_query = count_query.where(RunRecord.status == status)
        total = int(session.scalar(count_query) or 0)
        records = list(
            session.scalars(
                query.order_by(RunRecord.start_time.desc()).offset((page - 1) * page_size).limit(page_size)
            ).all()
        )
        telemetry = _llm_stats_by_run(session, [record.run_id for record in records])
    store.close()
    return {
        "items": [_run_summary(record, telemetry.get(record.run_id)) for record in records],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@v1.get("/api/targets")
def list_targets():
    """Return target portfolio summaries using persisted campaign and finding data."""
    store = SQLiteStore(Path(settings.db_path))
    with store.SessionLocal() as session:
        runs = list(session.scalars(select(RunRecord).order_by(RunRecord.start_time.desc())).all())
        findings = list(session.scalars(select(FindingRecord)).all())
    store.close()

    summaries: Dict[str, Dict] = {}
    for run in runs:
        if not run.target_id:
            continue
        entry = summaries.setdefault(run.target_id, {
            "target_id": run.target_id,
            "campaign_count": 0,
            "latest_run": None,
            "open_findings": 0,
        })
        entry["campaign_count"] += 1
        if entry["latest_run"] is None:
            entry["latest_run"] = _run_summary(run)
    for finding in findings:
        if finding.status == "open" and finding.target_id in summaries:
            summaries[finding.target_id]["open_findings"] += 1
    return {"items": list(summaries.values())}



@v1.get("/api/runs/{run_id}")
def get_run(run_id: str):
    """Retrieve detailed state of a specific run."""
    store = SQLiteStore(Path(settings.db_path))
    with store.SessionLocal() as session:
        # Check run
        stmt = select(RunRecord).where(RunRecord.run_id == run_id)
        run = session.scalar(stmt)
        if not run:
            store.close()
            raise HTTPException(status_code=404, detail="Run not found")

        # Get attacks
        stmt_attacks = select(AttackRecord).where(AttackRecord.run_id == run_id)
        attacks = session.scalars(stmt_attacks).all()
        llm_calls = session.scalars(
            select(LLMCallRecord).where(LLMCallRecord.run_id == run_id)
        ).all()
        llm_telemetry = [
            {
                "id": c.id,
                "agent": c.agent_name,
                "model": c.deployment,
                "latency_ms": round((c.latency or 0) * 1000, 2),
                "prompt_tokens": c.prompt_tokens or 0,
                "completion_tokens": c.completion_tokens or 0,
                "total_tokens": (c.prompt_tokens or 0) + (c.completion_tokens or 0),
                "input_hash": c.input_hash,
                "output_hash": c.output_hash,
                "timestamp": c.timestamp.isoformat() if c.timestamp else None,
            }
            for c in llm_calls
        ]

        # Build response
        result = {
            "run_id": run.run_id,
            "target_id": run.target_id,
            "status": run.status,
            "error": run.error,
            "start_time": run.start_time.isoformat() if run.start_time else None,
            "end_time": run.end_time.isoformat() if run.end_time else None,
            "total_attacks": run.total_attacks,
            "successful_attacks": run.successful_attacks,
            "success_rate": run.success_rate,
            "llm_calls": llm_telemetry,
            "llm_stats": {
                "calls": len(llm_telemetry),
                "prompt_tokens": sum(c["prompt_tokens"] for c in llm_telemetry),
                "completion_tokens": sum(c["completion_tokens"] for c in llm_telemetry),
                "total_tokens": sum(c["total_tokens"] for c in llm_telemetry),
                "latency_ms": round(sum(c["latency_ms"] for c in llm_telemetry), 2),
            },
            "attacks": [
                {
                    "id": a.id,
                    "attempt_number": a.attempt_number,
                    "strategy_type": a.strategy_type,
                    "target_id": a.target_id,
                    "finding_id": a.finding_id,
                    "prompt": a.prompt,
                    "response": a.response,
                    "success": bool(a.success),
                    "severity": a.severity,
                    "score": a.score,
                    "score_threshold": a.score_threshold,
                    "indicators": a.indicators,
                    "observation": (a.indicators or {}).get("_observation"),
                    "error": a.error,
                    "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                }
                for a in attacks
            ],
        }

    store.close()
    return result


@v1.get("/api/runs/{run_id}/analysis-report")
def get_analysis_report(run_id: str):
    """Exposes the run as the structured AnalysisReport expected by the React frontend."""
    store = SQLiteStore(Path(settings.db_path))
    with store.SessionLocal() as session:
        # Get run record
        stmt = select(RunRecord).where(RunRecord.run_id == run_id)
        run = session.scalar(stmt)
        if not run:
            store.close()
            raise HTTPException(status_code=404, detail="Run not found")

        # Get attacks
        stmt_attacks = select(AttackRecord).where(AttackRecord.run_id == run_id)
        attacks = session.scalars(stmt_attacks).all()

    store.close()

    # Load report JSON if exists
    report_file = Path(settings.report_output_dir) / f"{run_id}_report.json"
    narratives = {}
    recommendations = []
    if report_file.exists():
        try:
            with open(report_file, "r") as f:
                report_data = json.load(f)
                narratives = report_data.get("narratives", {})
                recommendations = report_data.get("recommendations", [])
        except Exception as e:
            logger.error(f"[API] Error loading JSON report {report_file}: {e}")

    # Narratives come ONLY from the real LLM-generated report. We never
    # fabricate security analysis: a missing narrative is reported as a
    # factual statement of absence, not an invented vulnerability claim.
    # The executive summary may fall back to a purely factual restatement
    # of the recorded attack counts (no interpretation).
    executive_summary = narratives.get(
        "executive_summary",
        f"Red team run against target {run.target_id}: "
        f"{run.total_attacks} attacks executed, {run.successful_attacks} successful. "
        f"No narrative report was generated for this run."
        if not narratives
        else "",
    )
    vulnerabilities_found = narratives.get("vulnerabilities_found", "")
    remaining_risks = narratives.get("remaining_risks", "")
    attack_campaign = narratives.get("attack_campaign", "")

    # Calculate average confidence based on scores
    avg_score = sum(a.score for a in attacks) / len(attacks) if attacks else 0.5
    confidence_percentage = int(avg_score * 100)

    # Determine maximum severity
    severities = [a.severity for a in attacks]
    if "critical" in severities:
        max_severity = "Critical"
    elif "high" in severities:
        max_severity = "High"
    elif "medium" in severities:
        max_severity = "Medium"
    else:
        max_severity = "Low"

    # Find the payload and output of a successful attack, or default to first
    successful_attacks_list = [a for a in attacks if a.success]
    primary_attack = successful_attacks_list[0] if successful_attacks_list else (attacks[0] if attacks else None)

    attack_payload = primary_attack.prompt if primary_attack else "No attacks executed."
    raw_output = primary_attack.response if primary_attack else "No response recorded."

    # Construct step-by-step trace
    trace = []
    # 1. Start trace
    trace.append({
        "time": "0.0s",
        "action": "Strategist Assessment",
        "details": f"Strategist selected risk profile for {run.target_id}",
        "status": "passed",
    })

    # 2. Attack attempts as trace steps
    for idx, a in enumerate(attacks, 1):
        status = "failed" if a.success else "passed"
        outcome = "breached security boundaries" if a.success else "blocked by safety rules"
        trace.append({
            "time": f"{idx * 15}s",
            "action": f"Adversarial Probe {idx}",
            "details": f"Attempted {a.strategy_type}: {outcome} (score {a.score:.2f})",
            "status": status,
        })

    return {
        "id": run_id,
        "agent": run.target_id,
        # Map back to UI values
        "type": "Prompt Injection" if "injection" in (primary_attack.strategy_type if primary_attack else "") else "Tool Misuse",
        "intensity": "Medium",
        "summary": executive_summary,
        "rootCause": vulnerabilities_found,
        "businessImpact": remaining_risks,
        "policyGap": attack_campaign,
        "confidence": confidence_percentage,
        "severity": max_severity,
        "trace": trace,
        "attackPayload": attack_payload,
        "rawOutput": raw_output,
        "recommendations": recommendations,
    }


@v1.get("/api/runs/{run_id}/report-markdown")
def get_report_markdown(run_id: str):
    """Serve the raw markdown report generated by the ReporterAgent."""
    report_file = Path(settings.report_output_dir) / f"{run_id}_report.md"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Markdown report not found")
    return {"run_id": run_id, "markdown": report_file.read_text()}


@v1.get("/api/open-findings")
def get_open_findings(target_id: Optional[str] = None):
    """Return findings with no passing retest across all historical runs."""
    store = SQLiteStore(Path(settings.db_path))
    findings = store.get_findings(status="open", target_id=target_id)
    store.close()
    return findings



@v1.get("/api/findings")
def list_findings(
    target_id: Optional[str] = None,
    asi_class: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
):
    """Paginated findings list with optional filters."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_findings(
        target_id=target_id,
        asi_class=asi_class,
        status=status,
        severity=severity,
        page=page,
        page_size=page_size,
    )
    store.close()
    return result


@v1.get("/api/findings/{finding_id}")
def get_finding(finding_id: str):
    """Single finding with its most recent evaluator verdict."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_finding(finding_id)
    store.close()
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@v1.get("/api/findings/{finding_id}/attempts")
def get_finding_attempts(finding_id: str):
    """All attack records that contributed to a finding across all runs."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_finding_attempts(finding_id)
    store.close()
    return result



@v1.get("/api/targets/{target_id:path}/coverage")
def get_target_coverage(target_id: str):
    """Which ASI classes have been tested and which have open findings."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_target_coverage(target_id)
    store.close()
    return result


@v1.get("/api/targets/{target_id:path}/trends")
def get_target_trends(target_id: str, days: int = 30):
    """Success rate per strategy per day for the last N days."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_target_trends(target_id, days=days)
    store.close()
    return result


@v1.get("/api/runs/{run_id}/findings")
def get_run_findings(run_id: str):
    """All findings first seen or updated in this run."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_run_findings(run_id)
    store.close()
    return result


@v1.get("/api/incidents")
def get_incidents():
    """Retrieve all historical attacks to populate the live incident feed on the dashboard."""
    store = SQLiteStore(Path(settings.db_path))
    incidents = []
    with store.SessionLocal() as session:
        # Query recent attacks across all runs
        stmt = select(AttackRecord).order_by(AttackRecord.timestamp.desc()).limit(20)
        attacks = session.scalars(stmt).all()

        for a in attacks:
            # Find associated target_id
            stmt_run = select(RunRecord).where(RunRecord.run_id == a.run_id)
            run = session.scalar(stmt_run)
            target = run.target_id if run else "Agent"

            # Format timestamp nicely (e.g. "12m ago" or ISO date)
            dt = a.timestamp
            now = datetime.utcnow()
            diff = now - dt
            if diff.days > 0:
                time_str = f"{diff.days}d ago"
            elif diff.seconds // 3600 > 0:
                time_str = f"{diff.seconds // 3600}h ago"
            elif diff.seconds // 60 > 0:
                time_str = f"{diff.seconds // 60}m ago"
            else:
                time_str = "just now"

            # Map the persisted strategy to the same canonical labels used by
            # the frontend. Never default unknown strategies to Prompt Injection.
            ui_type = _STRATEGY_TO_UI_TYPE.get(
                a.strategy_type,
                a.strategy_type.replace("_", " ").title(),
            )

            status = "Critical" if a.success else "Blocked"
            if a.severity == "medium" and not a.success:
                status = "Warning"

            incidents.append({
                "id": f"INC-{a.id}",
                "run_id": a.run_id,
                "timestamp": time_str,
                "agent": target,
                "type": ui_type,
                "riskScore": int(a.score * 100),
                "status": status,
                "details": a.prompt[:100] + "..." if len(a.prompt) > 100 else a.prompt,
            })

    store.close()
    return incidents



_STRATEGY_TO_UI_TYPE: Dict[str, str] = {
    "prompt_injection": "Prompt Injection",
    "memory_poisoning": "Memory Poisoning",
    "tool_misuse": "Tool Misuse",
    "jailbreak": "Privilege Escalation",
    "instruction_hierarchy": "Goal Hijacking",
    "sensitive_data_exposure": "Data Exfiltration",
    "indirect_injection": "Data Exfiltration",
    "leakage": "Data Exfiltration",
    "retrieval_poisoning": "Supply Chain Attack",
    "workflow_manipulation": "Agent DoS",
}


# ── API v2 routers (WP7 control plane, WP8 resources and auth) ───────────────
from cyberredteam.api_v2.auth_routes import router as _auth_router  # noqa: E402
from cyberredteam.api_v2.campaigns import router as _campaigns_router  # noqa: E402
from cyberredteam.api_v2.evidence import conversations as _conversations_router  # noqa: E402
from cyberredteam.api_v2.evidence import findings as _findings_router  # noqa: E402
from cyberredteam.api_v2.reports import router as _reports_router  # noqa: E402
from cyberredteam.api_v2.targets import router as _targets_router  # noqa: E402
from cyberredteam.jobs.api_v2 import router as _jobs_router  # noqa: E402

app.include_router(v1)
for _router in (
    _auth_router, _targets_router, _campaigns_router, _jobs_router,
    _conversations_router, _findings_router, _reports_router,
):
    app.include_router(_router)


def v2_openapi() -> Dict[str, Any]:
    """The OpenAPI document restricted to /api/v2 (for frontend type generation)."""
    spec = app.openapi()
    return {**spec, "paths": {p: v for p, v in spec["paths"].items() if p.startswith("/api/v2")}}
