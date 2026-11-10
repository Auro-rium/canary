"""FastAPI web server for integrating the red team backend with the React frontend."""

import json
import logging
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, HttpUrl, TypeAdapter, ValidationError
from sqlalchemy import func, select

from cyberredteam.contracts import TargetConfig, normalize_asi_code
from cyberredteam.evaluation.taxonomy import lookup as taxonomy_lookup
from cyberredteam.langgraph.orchestrator import GraphOrchestrator
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import RunConfig, StrategyType
from cyberredteam.security.ownership import (
    DNS_TXT_PREFIX,
    VERIFY_HEADER,
    WELL_KNOWN_PATH,
    TargetRefused,
    check_target_urls,
    verify_ownership,
)
from cyberredteam.security.targets import InMemoryTargetStore, TargetStore
from cyberredteam.security.tokens import hash_verification_token, issue_verification_token
from cyberredteam.settings import get_settings
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import AttackRecord, FindingRecord, LLMCallRecord, RunRecord

logger = logging.getLogger("cyberredteam.api")
logging.basicConfig(level=logging.INFO)

settings = get_settings()
setup_logging(settings.log_level, settings.log_file)


def require_auth(authorization: Optional[str] = Header(None)) -> None:
    """Require a valid bearer token on every request.

    The token must equal ``API_SECRET_KEY`` (matched to the frontend's
    ``VITE_API_TOKEN``). Fails closed: if no key is configured the API
    refuses all requests rather than running wide open.
    """
    if not settings.api_secret_key:
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured (set API_SECRET_KEY).",
        )
    scheme, _, token = (authorization or "").partition(" ")
    if scheme != "Bearer" or token != settings.api_secret_key:
        raise HTTPException(status_code=401, detail="Invalid or missing bearer token")


def _authorized_targets() -> list[str]:
    return [t.strip() for t in settings.allowed_targets.split(",") if t.strip()]


# ── Registered targets (WP1) ─────────────────────────────────────────────────
# Module-level store behind a dependency so WP6 can swap in the SQL store (or a
# test can override it) without touching the routes.
_target_store: TargetStore = InMemoryTargetStore()


def get_target_store() -> TargetStore:
    return _target_store


def get_ownership_options() -> Dict[str, Any]:
    """Keyword options for ``verify_ownership``.

    Private/loopback targets stay refused here; tests override this dependency
    to inject fake transports and resolvers.
    """
    return {"allow_private_targets": False}


_URL_ADAPTER = TypeAdapter(HttpUrl)

_NOT_VERIFIED_DETAIL = (
    "Target is not a registered, ownership-verified target. Register it with "
    "POST /api/v2/targets and verify it with POST /api/v2/targets/{id}/verify first."
)


def _normalize_endpoint(raw: str) -> Optional[str]:
    try:
        return str(_URL_ADAPTER.validate_python(raw.strip()))
    except ValidationError:
        return None


def _require_verified_target(
    store: TargetStore,
    target_ref: Optional[str] = None,
    endpoint: Optional[str] = None,
) -> TargetConfig:
    """Resolve a campaign's target to a registered, verified target or raise 403.

    ``target_ref`` is a registered target_id; ``endpoint`` (legacy UI field) must
    equal the endpoint of a verified target. There is no fail-open path: an
    unknown, unverified or empty reference is always refused. When
    ``ALLOWED_TARGETS`` is set it narrows further (by target_id or endpoint).
    """
    try:
        target: Optional[TargetConfig] = None
        if target_ref and target_ref.strip():
            target = store.get(target_ref.strip())
        if target is None and endpoint and endpoint.strip():
            wanted = _normalize_endpoint(endpoint)
            if wanted is not None:
                target = next(
                    (t for t in store.list() if t.verified and str(t.endpoint) == wanted),
                    None,
                )
    except RuntimeError:
        # Secret decryption failed (e.g. CANARY_ENCRYPTION_KEY missing): fail closed.
        raise HTTPException(status_code=503, detail="Target store is unavailable.") from None
    if target is None or not target.verified:
        raise HTTPException(status_code=403, detail=_NOT_VERIFIED_DETAIL)
    allowed = _authorized_targets()
    if allowed and target.target_id not in allowed and str(target.endpoint) not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Target '{target.target_id}' is not in the authorized allowlist.",
        )
    return target


# Auth is enforced on every route via the app-level dependency.
app = FastAPI(
    title="Agent Canary Red Team API Backend",
    dependencies=[Depends(require_auth)],
)

# Enable CORS for the React frontend. Auth is via bearer token (not cookies),
# so credentials are not allowed and a wildcard origin is safe.
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


class RunRequest(BaseModel):
    target_id: str
    strategy: Optional[str] = None
    intensity: Optional[str] = "Medium"


# Active background runs cache to track running orchestrators
active_runs: Dict[str, str] = {}

# Lock to coordinate concurrent run registration and status updates.
# Note: this lock only serializes access within a single running API server process
# and cannot coordinate against separately-invoked `cyber-rt run` CLI processes
# (which are different OS processes with no shared memory). Cross-process coordination
# is an accepted limitation for this dev/demo tool.
_active_runs_lock = threading.Lock()


def _running_count() -> int:
    """Count running runs from SQLite so restarts do not lose lifecycle state."""
    try:
        store = SQLiteStore(Path(settings.db_path))
        with store.SessionLocal() as session:
            count = len(session.scalars(select(RunRecord).where(RunRecord.status == "running")).all())
        store.close()
        return count
    except Exception as exc:
        logger.warning("Could not read persisted run count: %s", exc)
        return sum(1 for v in active_runs.values() if v == "running")


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


def run_orchestrator_thread(
    run_id: str,
    target_id: str,
    strategy_types: List[StrategyType],
    max_iterations: int,
    max_attempts: int,
    target_headers: Optional[Dict[str, str]] = None,
    target_request_template: Optional[str] = None,
    target_response_path: Optional[str] = None,
):
    """Run the LangGraph workflow in a background thread."""
    try:
        logger.info(f"[API] Starting background run {run_id} against {target_id}")
        config = RunConfig(
            run_id=run_id,
            target_id=target_id,
            strategy_types=strategy_types,
            max_attempts=max_attempts,
            description=f"UI Triggered Run on {target_id}",
            target_headers=target_headers or {},
            target_request_template=target_request_template,
            target_response_path=target_response_path,
        )
        orchestrator = GraphOrchestrator(
            config=config,
            db_path=settings.db_path,
            report_dir=settings.report_output_dir,
            max_iterations=max_iterations,
        )
        orchestrator.run()
        with _active_runs_lock:
            active_runs[run_id] = "completed"
        logger.info(f"[API] Run {run_id} completed successfully")
    except Exception as e:
        logger.error(f"[API] Run {run_id} failed: {e}")
        with _active_runs_lock:
            active_runs[run_id] = "failed"
        # Update DB status to failed
        try:
            store = SQLiteStore(Path(settings.db_path))
            with store.SessionLocal() as session:
                stmt = select(RunRecord).where(RunRecord.run_id == run_id)
                run = session.scalar(stmt)
                if run:
                    run.status = "failed"
                    run.error = str(e)
                    run.end_time = datetime.utcnow()
                    session.commit()
            store.close()
        except Exception as dbe:
            logger.error(f"[API] Failed to update failed status in DB: {dbe}")


@app.get("/api/status")
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


@app.get("/api/dashboard/overview")
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


@app.get("/api/runs")
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


@app.get("/api/targets")
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


@app.post("/api/runs")
def create_run(
    req: RunRequest,
    background_tasks: BackgroundTasks,
    store: TargetStore = Depends(get_target_store),
):
    """Trigger a new red team run against a registered, verified target."""
    # Authorization scope: only ownership-verified targets (checked before a
    # concurrency slot is taken, so a refusal never leaks one).
    target = _require_verified_target(store, target_ref=req.target_id)
    target_id = str(target.endpoint)

    with _active_runs_lock:
        if _running_count() >= settings.max_concurrent_runs:
            raise HTTPException(
                status_code=429,
                detail=f"Maximum concurrent runs ({settings.max_concurrent_runs}) reached. Try again once a run completes.",
            )
        run_id = uuid.uuid4().hex[:8]
        active_runs[run_id] = "running"

    # Map UI strategies to StrategyType values
    strategy_mapping = {
        "Prompt Injection": StrategyType.PROMPT_INJECTION,
        "Data Exfiltration": StrategyType.INDIRECT_INJECTION,
        "Privilege Escalation": StrategyType.JAILBREAK,
        "Tool Misuse": StrategyType.TOOL_MISUSE,
    }

    selected_strategy = req.strategy
    if selected_strategy in strategy_mapping:
        strategies = [strategy_mapping[selected_strategy]]
    else:
        # Default strategy mix if none matches
        strategies = [
            StrategyType.PROMPT_INJECTION,
            StrategyType.INDIRECT_INJECTION,
            StrategyType.TOOL_MISUSE,
        ]

    # Map UI intensity to iterations & attempts
    intensity_mapping = {
        "Low": (1, 2),
        "Medium": (2, 4),
        "High": (3, 5),
    }
    max_iterations, max_attempts = intensity_mapping.get(req.intensity or "Medium", (2, 4))

    # Initialize SQLite store to record start of run
    store = SQLiteStore(Path(settings.db_path))
    store.save_run_start(run_id, target_id)
    store.close()

    # Start the LangGraph workflow in a separate background thread
    t = threading.Thread(
        target=run_orchestrator_thread,
        args=(run_id, target_id, strategies, max_iterations, max_attempts),
        daemon=True,
    )
    t.start()

    return {
        "run_id": run_id,
        "status": "running",
        "target_id": target.target_id,
        "endpoint": target_id,
    }


@app.get("/api/runs/{run_id}")
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


@app.get("/api/runs/{run_id}/analysis-report")
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


@app.get("/api/runs/{run_id}/report-markdown")
def get_report_markdown(run_id: str):
    """Serve the raw markdown report generated by the ReporterAgent."""
    report_file = Path(settings.report_output_dir) / f"{run_id}_report.md"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Markdown report not found")
    return {"run_id": run_id, "markdown": report_file.read_text()}


@app.get("/api/open-findings")
def get_open_findings(target_id: Optional[str] = None):
    """Return findings with no passing retest across all historical runs."""
    store = SQLiteStore(Path(settings.db_path))
    findings = store.get_findings(status="open", target_id=target_id)
    store.close()
    return findings


# ── Phase 3: Findings endpoints ──────────────────────────────────────────────

class FindingStatusUpdate(BaseModel):
    status: str
    reviewer_id: Optional[str] = None
    rationale: Optional[str] = None


@app.get("/api/findings")
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


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str):
    """Single finding with its most recent evaluator verdict."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_finding(finding_id)
    store.close()
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return result


@app.get("/api/findings/{finding_id}/attempts")
def get_finding_attempts(finding_id: str):
    """All attack records that contributed to a finding across all runs."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_finding_attempts(finding_id)
    store.close()
    return result


@app.put("/api/findings/{finding_id}/status")
def update_finding_status(finding_id: str, body: FindingStatusUpdate):
    """Manual lifecycle transition for a finding.

    Enforces the transition rules defined in artifact_store.py.
    Returns 409 for illegal transitions.
    """
    store = SQLiteStore(Path(settings.db_path))
    try:
        store.transition_finding_status(
            finding_id,
            body.status,
            {
                "reviewer_id": body.reviewer_id,
                "rationale": body.rationale,
            },
        )
    except ValueError as e:
        store.close()
        raise HTTPException(status_code=409, detail=str(e))
    store.close()
    return {"status": "ok", "finding_id": finding_id, "new_status": body.status}


@app.get("/api/targets/{target_id:path}/coverage")
def get_target_coverage(target_id: str):
    """Which ASI classes have been tested and which have open findings."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_target_coverage(target_id)
    store.close()
    return result


@app.get("/api/targets/{target_id:path}/trends")
def get_target_trends(target_id: str, days: int = 30):
    """Success rate per strategy per day for the last N days."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_target_trends(target_id, days=days)
    store.close()
    return result


@app.get("/api/runs/{run_id}/findings")
def get_run_findings(run_id: str):
    """All findings first seen or updated in this run."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_run_findings(run_id)
    store.close()
    return result


@app.get("/api/incidents")
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


# ── SSE Campaign Endpoint ─────────────────────────────────────────────────────

_TECHNIQUE_TO_STRATEGY: Dict[str, StrategyType] = {
    "prompt-injection":     StrategyType.PROMPT_INJECTION,
    "memory-poisoning":     StrategyType.MEMORY_POISONING,
    "tool-abuse":           StrategyType.TOOL_MISUSE,
    "privilege-escalation": StrategyType.JAILBREAK,
    "goal-hijacking":       StrategyType.INSTRUCTION_HIERARCHY,
    "data-exfiltration":    StrategyType.SENSITIVE_DATA_EXPOSURE,
    "supply-chain":         StrategyType.RETRIEVAL_POISONING,
    "denial-of-service":    StrategyType.WORKFLOW_MANIPULATION,
}

# Fallback ASI class per strategy, derived from configs/asi_taxonomy.yaml (the
# source of truth) so the UI and the evaluator never disagree. Canonical form
# is "ASI01".."ASI10".
_STRATEGY_TO_ASI: Dict[str, str] = {
    s.value: taxonomy_lookup(s.value, "*")[0] for s in StrategyType
}


def _finding_asi_code(indicators: dict, strategy: str) -> str:
    """Canonical ASI code for a finding; legacy "ASI-01" values are normalised."""
    try:
        code = normalize_asi_code(indicators.get("asi_class"))
    except ValueError:
        code = None
    return code or _STRATEGY_TO_ASI.get(strategy) or taxonomy_lookup(strategy, "*")[0]


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

# Severity values accepted by FindingPayload on the frontend.
# AttackSeverity.INFO ("info") is a valid backend enum value but is not part of
# the frontend union type ('CRITICAL'|'HIGH'|'MEDIUM'|'LOW'); clamp it to 'LOW'.
_VALID_FINDING_SEVERITIES: frozenset = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})

# Normalise evaluator verdict_path values to the two-member union the frontend
# declares: 'consensus' | 'heuristic_fallback'.
# - deterministic_only → consensus   (deterministic signal is reliable, not heuristic)
# - llm_only           → heuristic_fallback (LLM alone is uncertain, unconfirmed)
_VERDICT_PATH_NORM: Dict[str, str] = {
    "consensus":          "consensus",
    "deterministic_only": "consensus",
    "llm_only":           "heuristic_fallback",
    "heuristic_fallback": "heuristic_fallback",
}


class CampaignRunRequest(BaseModel):
    campaign_id: str
    # A registered, verified target: by id (preferred) or by its exact endpoint.
    target_id: Optional[str] = None
    target_url: str = ""
    techniques: List[str]
    # Generic HTTP target config — see HttpTargetAdapter for the contract.
    headers: Dict[str, str] = {}
    request_template: Optional[str] = None
    response_path: Optional[str] = None


def _build_finding(atk: AttackRecord, run_id: str) -> dict:
    """Convert an AttackRecord to a FindingPayload dict (frontend schema)."""
    indicators = atk.indicators or {}
    verdict = "VULNERABLE" if atk.success else "RESILIENT"
    sev = (atk.severity or "high").upper()
    # Clamp severity: 'INFO' is a valid backend enum value but is not in the
    # frontend FindingPayload union type ('CRITICAL'|'HIGH'|'MEDIUM'|'LOW').
    if sev not in _VALID_FINDING_SEVERITIES:
        sev = "LOW"
    raw_vp = indicators.get("verdict_path", "consensus")
    # Normalise verdict_path to the two values the frontend union type allows.
    vp = _VERDICT_PATH_NORM.get(raw_vp, "heuristic_fallback")
    return {
        "finding_id": atk.finding_id or f"{run_id}{atk.id:04x}",
        "technique_id": atk.strategy_type,
        "asi_code": _finding_asi_code(indicators, atk.strategy_type),
        "severity": sev,
        "verdict": verdict,
        "verdict_path": vp,
        "score": float(atk.score or 0.0),
        "adversarial_input": atk.prompt or "",
        "target_response_summary": (atk.response or "")[:300],
        "deterministic_hits": indicators.get("deterministic_hits", []),
        "threshold_used": float(atk.score_threshold or 0.5),
        "recommendation": indicators.get(
            "recommendation",
            "Harden the target's system prompt and add input validation guardrails.",
        ),
    }


@app.post("/api/campaigns/run")
async def campaign_run_sse(
    req: CampaignRunRequest,
    store: TargetStore = Depends(get_target_store),
):
    """Start a red-team campaign and stream SSE events back to the browser.

    Event types: agent_state | log | finding | campaign_complete
    Each line: ``data: <json>\\n\\n``
    """
    import asyncio

    # Map technique slugs → StrategyType
    strategies = [
        _TECHNIQUE_TO_STRATEGY[t]
        for t in req.techniques
        if t in _TECHNIQUE_TO_STRATEGY
    ]
    if not strategies:
        strategies = [StrategyType.PROMPT_INJECTION]

    # Only a registered, ownership-verified target may be attacked. The stored
    # endpoint is used verbatim: no rewriting, no default target.
    target = _require_verified_target(store, target_ref=req.target_id, endpoint=req.target_url)
    target_id = str(target.endpoint)

    with _active_runs_lock:
        if _running_count() >= settings.max_concurrent_runs:
            raise HTTPException(
                status_code=429,
                detail=f"Maximum concurrent runs ({settings.max_concurrent_runs}) reached. Try again once a run completes.",
            )
        run_id = uuid.uuid4().hex[:8]
        active_runs[run_id] = "running"

    store = SQLiteStore(Path(settings.db_path))
    store.save_run_start(run_id, target_id)
    store.close()

    # Launch orchestrator in a background thread (non-blocking)
    t = threading.Thread(
        target=run_orchestrator_thread,
        args=(run_id, target_id, strategies, 3, max(4, len(strategies) * 2)),
        kwargs={
            "target_headers": req.headers,
            "target_request_template": req.request_template,
            "target_response_path": req.response_path,
        },
        daemon=True,
    )
    t.start()

    async def generate():
        def sse(data: dict) -> str:
            data.setdefault("timestamp", datetime.utcnow().isoformat())
            return f"data: {json.dumps(data)}\n\n"

        campaign_id = req.campaign_id

        # ── Phase: startup ────────────────────────────────────────────────────
        yield sse({"type": "log", "payload": {
            "level": "SYSTEM",
            "message": f"Campaign {campaign_id} initialised. {len(req.techniques)} technique(s) queued.",
        }})

        await asyncio.sleep(0.5)
        yield sse({"type": "agent_state", "payload": {"agent_id": "orchestrator", "status": "active"}})

        await asyncio.sleep(0.8)
        yield sse({"type": "agent_state", "payload": {"agent_id": "orchestrator", "status": "processing"}})
        yield sse({"type": "log", "payload": {
            "level": "SYSTEM", "message": "Orchestrator online. Dispatching agent pipeline.",
        }})

        await asyncio.sleep(1.0)
        yield sse({"type": "agent_state", "payload": {
            "agent_id": "strategist", "status": "active", "active_edge": "orchestrator->strategist",
        }})
        await asyncio.sleep(0.8)
        yield sse({"type": "log", "payload": {
            "level": "SYSTEM", "message": "Strategist agent selecting attack strategies.",
        }})
        await asyncio.sleep(0.6)
        yield sse({"type": "agent_state", "payload": {
            "agent_id": "strategist", "status": "done", "active_edge": "strategist->attacker",
        }})
        yield sse({"type": "agent_state", "payload": {
            "agent_id": "attacker", "status": "active", "active_edge": "orchestrator->attacker",
        }})

        await asyncio.sleep(0.6)
        yield sse({"type": "agent_state", "payload": {"agent_id": "attacker", "status": "processing"}})
        yield sse({"type": "log", "payload": {
            "level": "ATTACK",
            "message": f"Attacker agent online. Dispatching {len(strategies)} strategy probe(s) against {target_id}.",
        }})

        await asyncio.sleep(1.5)
        yield sse({"type": "agent_state", "payload": {
            "agent_id": "target", "status": "active", "active_edge": "attacker->target",
        }})
        yield sse({"type": "log", "payload": {
            "level": "ATTACK", "message": "Attack probes dispatched. Awaiting target responses.",
        }})

        # ── Phase: poll for real results ──────────────────────────────────────
        last_attack_count = 0
        elapsed = 0
        max_wait = 1800  # seconds (30 min — generous cap for multi-strategy/multi-iteration LLM runs)

        while elapsed < max_wait:
            await asyncio.sleep(4)
            elapsed += 4

            try:
                def _read_db():
                    s = SQLiteStore(Path(settings.db_path))
                    with s.SessionLocal() as sess:
                        run_rec = sess.scalar(select(RunRecord).where(RunRecord.run_id == run_id))
                        atks = list(sess.scalars(select(AttackRecord).where(AttackRecord.run_id == run_id)).all())
                        status = run_rec.status if run_rec else "running"
                        run_error = run_rec.error if run_rec else None
                    s.close()
                    return status, run_error, atks

                current_status, run_error, attacks = await asyncio.to_thread(_read_db)
            except Exception as exc:
                logger.warning(f"[SSE] DB poll error: {exc}")
                current_status = active_runs.get(run_id, "running")
                run_error = str(exc)
                attacks = []

            # Emit new attack results
            if len(attacks) > last_attack_count:
                new_attacks = attacks[last_attack_count:]
                last_attack_count = len(attacks)

                for atk in new_attacks:
                    observation = (atk.indicators or {}).get("_observation", {})
                    target_status = observation.get("http_status", "n/a")
                    target_state = observation.get("status", "not_recorded")
                    yield sse({"type": "log", "payload": {
                        "level": "EVAL",
                        "message": (
                            f"Target observation: {target_state} / HTTP {target_status} / "
                            f"{observation.get('latency_ms', 'n/a')}ms for {atk.strategy_type}."
                            if observation else
                            f"No target observation recorded for {atk.strategy_type}: "
                            f"{atk.error or 'unknown execution error'}."
                        ),
                    }})
                    yield sse({"type": "agent_state", "payload": {
                        "agent_id": "evaluator", "status": "processing", "active_edge": "evaluator->target",
                    }})

                    await asyncio.sleep(0.5)

                    finding = _build_finding(atk, run_id)

                    if atk.success:
                        yield sse({"type": "agent_state", "payload": {
                            "agent_id": "evaluator", "status": "done", "active_edge": "evaluator->findings",
                        }})
                        yield sse({"type": "finding", "payload": finding})
                        yield sse({"type": "log", "payload": {
                            "level": "FINDING",
                            "message": f"{finding['severity']}: {finding['asi_code']} — VULNERABLE  score={atk.score:.2f}",
                        }})
                    else:
                        yield sse({"type": "agent_state", "payload": {"agent_id": "evaluator", "status": "done"}})
                        yield sse({"type": "log", "payload": {
                            "level": "EVAL",
                            "message": f"Probe blocked. Score={atk.score:.2f} below threshold {atk.score_threshold:.2f}.",
                        }})

            # Heartbeat log every 20 s
            if elapsed % 20 == 0 and elapsed > 0:
                yield sse({"type": "log", "payload": {
                    "level": "SYSTEM",
                    "message": f"Run {run_id} — {elapsed}s elapsed — {last_attack_count} probe(s) recorded.",
                }})

            if current_status in ("completed", "failed"):
                break

        if elapsed >= max_wait and current_status not in ("completed", "failed"):
            yield sse({"type": "log", "payload": {
                "level": "SYSTEM",
                "message": f"Display timeout reached ({max_wait}s) — the campaign is still running in the background and results may be incomplete. Check the full report later.",
            }})

        # Never turn a failed or still-running backend run into a successful
        # browser report. The real agent pipeline is authoritative; if it did
        # not complete, the UI must receive an explicit failure event.
        if current_status != "completed":
            failed = current_status == "failed"
            message = (
                f"Real agent pipeline failed: {run_error or 'no error recorded'}."
                if failed
                else "Campaign is still running; no report is available yet."
            )
            yield sse({"type": "log", "payload": {
                "level": "ERROR" if failed else "SYSTEM",
                "message": message,
            }})
            yield sse({"type": "agent_state", "payload": {
                "agent_id": "orchestrator", "status": "error" if failed else "processing",
            }})
            yield sse({"type": "campaign_failed", "payload": {
                "campaign_id": campaign_id,
                "run_id": run_id,
                "status": current_status,
                "message": message,
            }})
            return

        # ── Phase: completion ───────────────────────────────────────────────
        yield sse({"type": "agent_state", "payload": {
            "agent_id": "reporter", "status": "active", "active_edge": "evaluator->reporter",
        }})
        await asyncio.sleep(0.8)
        yield sse({"type": "agent_state", "payload": {
            "agent_id": "reporter", "status": "done",
        }})
        yield sse({"type": "agent_state", "payload": {"agent_id": "orchestrator", "status": "done"}})
        yield sse({"type": "agent_state", "payload": {"agent_id": "attacker",     "status": "done"}})

        # Build final CompletePayload from DB
        try:
            def _final_read():
                s = SQLiteStore(Path(settings.db_path))
                with s.SessionLocal() as sess:
                    run_rec = sess.scalar(select(RunRecord).where(RunRecord.run_id == run_id))
                    all_atks = list(sess.scalars(select(AttackRecord).where(AttackRecord.run_id == run_id)).all())
                s.close()
                return run_rec, all_atks

            run_rec, all_atks = await asyncio.to_thread(_final_read)

            all_findings = [_build_finding(a, run_id) for a in all_atks]
            vulnerable = [f for f in all_findings if f["verdict"] == "VULNERABLE"]
            critical_count = len([f for f in vulnerable if f["severity"] == "CRITICAL"])
            high_count     = len([f for f in vulnerable if f["severity"] == "HIGH"])

            start_dt = run_rec.start_time if run_rec and run_rec.start_time else datetime.utcnow()
            duration = int((datetime.utcnow() - start_dt).total_seconds())

            complete_payload = {
                "campaign_id":    campaign_id,
                "run_id":         run_id,
                "total_findings": len(vulnerable),
                "critical_count": critical_count,
                "high_count":     high_count,
                "duration_seconds": max(elapsed, duration),
                "findings":       all_findings,
            }
        except Exception as exc:
            logger.error(f"[SSE] Final report build failed: {exc}")
            yield sse({"type": "log", "payload": {
                "level": "ERROR",
                "message": f"Final report assembly failed: {exc}",
            }})
            yield sse({"type": "campaign_failed", "payload": {
                "campaign_id": campaign_id,
                "run_id": run_id,
                "status": "failed",
                "message": f"Final report assembly failed: {exc}",
            }})
            return

        total = complete_payload["total_findings"]
        yield sse({"type": "log", "payload": {
            "level": "SYSTEM",
            "message": f"Campaign complete. {total} finding(s) confirmed. Report ready.",
        }})
        yield sse({"type": "campaign_complete", "payload": complete_payload})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── API v2: target registration and ownership verification (WP1) ─────────────

_V2_IGNORED_FIELDS = ("verified", "target_id", "allowed_auth_hosts")
_URL_CHECK_OPTIONS = ("allow_private_targets", "resolve_host")


def _target_view(target: TargetConfig, store: TargetStore) -> Dict[str, Any]:
    """Public view of a target: secrets masked, never the token or its hash."""
    view = target.model_dump(mode="json")  # SecretStr dumps as "**********"
    view["allowed_auth_hosts"] = store.get_allowed_auth_hosts(target.target_id)
    return view


def _parse_allowed_auth_hosts(raw: Any) -> List[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(h, str) and h.strip() for h in raw):
        raise HTTPException(status_code=422, detail="allowed_auth_hosts must be a list of hostnames")
    hosts = [h.strip().rstrip(".").lower() for h in raw]
    if any(c in h for h in hosts for c in "/:@ "):
        raise HTTPException(status_code=422, detail="allowed_auth_hosts entries must be bare hostnames")
    return hosts


def _verification_instructions(target: TargetConfig, token: str) -> Dict[str, Any]:
    host = target.endpoint.host or ""
    origin = f"{target.endpoint.scheme}://{host}"
    if target.endpoint.port and target.endpoint.port not in (80, 443):
        origin += f":{target.endpoint.port}"
    return {
        "http_wellknown": {"url": origin + WELL_KNOWN_PATH, "content": token},
        "dns_txt": {"name": DNS_TXT_PREFIX + host, "type": "TXT", "value": token},
        "response_header": {"header": VERIFY_HEADER, "value": token},
    }


@app.post("/api/v2/targets", status_code=201)
async def create_target_v2(
    request: Request,
    store: TargetStore = Depends(get_target_store),
    ownership_options: Dict[str, Any] = Depends(get_ownership_options),
):
    """Register an (unverified) target.

    The body is a ``TargetConfig`` without ``target_id``; any client-supplied
    ``verified`` or ``target_id`` is ignored. ``allowed_auth_hosts`` optionally
    lists extra hosts a ``token_url``/``login_url`` may live on. The plaintext
    verification token is returned in this response only; just its hash is kept.
    Validation errors never echo the submitted values (they may be secrets).
    """
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=422, detail="body must be a JSON object") from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="body must be a JSON object")

    allowed_auth_hosts = _parse_allowed_auth_hosts(body.get("allowed_auth_hosts"))
    data = {k: v for k, v in body.items() if k not in _V2_IGNORED_FIELDS}
    data["target_id"] = str(uuid.uuid4())
    try:
        config = TargetConfig.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(include_input=False, include_url=False, include_context=False),
        ) from None

    # Endpoint, token_url and login_url must be safe, public and host-bound.
    url_opts = {k: v for k, v in ownership_options.items() if k in _URL_CHECK_OPTIONS}
    try:
        # DNS resolution is blocking; keep it off the event loop.
        await run_in_threadpool(
            check_target_urls, str(config.endpoint), config.auth, allowed_auth_hosts, **url_opts
        )
    except TargetRefused as exc:
        raise HTTPException(status_code=422, detail=f"target refused: {exc}") from None

    token = issue_verification_token()
    try:
        target_id = store.create(config)
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Target secret storage is unavailable (CANARY_ENCRYPTION_KEY not configured).",
        ) from None
    store.set_verification_token_hash(target_id, hash_verification_token(token))
    store.set_allowed_auth_hosts(target_id, allowed_auth_hosts)
    logger.info("[API] registered target %s (unverified)", target_id)
    return {
        "target": _target_view(config, store),
        "verification_token": token,
        "verification": _verification_instructions(config, token),
    }


def _get_target_or_404(store: TargetStore, target_id: str) -> TargetConfig:
    try:
        target = store.get(target_id)
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Target store is unavailable.") from None
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@app.get("/api/v2/targets")
def list_targets_v2(store: TargetStore = Depends(get_target_store)):
    try:
        targets = store.list()
    except RuntimeError:
        raise HTTPException(status_code=503, detail="Target store is unavailable.") from None
    return {"items": [_target_view(t, store) for t in targets]}


@app.get("/api/v2/targets/{target_id}")
def get_target_v2(target_id: str, store: TargetStore = Depends(get_target_store)):
    return _target_view(_get_target_or_404(store, target_id), store)


class VerifyTargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["http_wellknown", "dns_txt", "response_header"]


@app.post("/api/v2/targets/{target_id}/verify")
def verify_target_v2(
    target_id: str,
    body: VerifyTargetRequest,
    store: TargetStore = Depends(get_target_store),
    ownership_options: Dict[str, Any] = Depends(get_ownership_options),
):
    """Run one ownership check. 200 either way; ``verified`` carries the outcome."""
    target = _get_target_or_404(store, target_id)
    token_hash = store.get_verification_token_hash(target_id)
    if not token_hash:
        raise HTTPException(status_code=409, detail="No verification token issued for this target")

    url_opts = {k: v for k, v in ownership_options.items() if k in _URL_CHECK_OPTIONS}
    try:
        # Re-checked at verify time: DNS may have changed since registration.
        check_target_urls(
            str(target.endpoint), target.auth, store.get_allowed_auth_hosts(target_id), **url_opts
        )
        result = verify_ownership(str(target.endpoint), token_hash, body.method, **ownership_options)
        verified, reason = result.verified, result.reason
    except TargetRefused as exc:
        verified, reason = False, f"refused: {exc}"

    if verified:
        store.set_verified(target_id, body.method)
        target = _get_target_or_404(store, target_id)
    logger.info(
        "[API] ownership check target=%s method=%s verified=%s", target_id, body.method, verified
    )
    return {
        "target": _target_view(target, store),
        "verified": verified,
        "method": body.method,
        "reason": reason,
    }
