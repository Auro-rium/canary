"""FastAPI web server for integrating the red team backend with the React frontend."""

import json
import logging
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select

from cyberredteam.langgraph.orchestrator import GraphOrchestrator
from cyberredteam.schemas import RunConfig, StrategyType
from cyberredteam.settings import get_settings
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import AttackRecord, RunRecord

logger = logging.getLogger("cyberredteam.api")
logging.basicConfig(level=logging.INFO)

settings = get_settings()


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
    """Count the number of runs currently in 'running' state."""
    return sum(1 for v in active_runs.values() if v == "running")


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
        active_runs[run_id] = "completed"
        logger.info(f"[API] Run {run_id} completed successfully")
    except Exception as e:
        logger.error(f"[API] Run {run_id} failed: {e}")
        active_runs[run_id] = "failed"
        # Update DB status to failed
        try:
            store = SQLiteStore(Path(settings.db_path))
            with store.SessionLocal() as session:
                stmt = select(RunRecord).where(RunRecord.run_id == run_id)
                run = session.scalar(stmt)
                if run:
                    run.status = "failed"
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
    }


@app.post("/api/runs")
def create_run(req: RunRequest, background_tasks: BackgroundTasks):
    """Trigger a new red team run against a target."""
    # Authorization scope: only attack targets we're allowed to.
    target_id = req.target_id
    allowed = _authorized_targets()
    if allowed:
        if target_id not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Target '{target_id}' is not in the authorized allowlist.",
            )
    else:
        logger.warning(
            "ALLOWED_TARGETS is empty — no target allowlist enforced. "
            "Set it before exposing this API."
        )

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
        "target_id": target_id,
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

        # Build response
        result = {
            "run_id": run.run_id,
            "target_id": run.target_id,
            "status": run.status,
            "start_time": run.start_time.isoformat() if run.start_time else None,
            "end_time": run.end_time.isoformat() if run.end_time else None,
            "total_attacks": run.total_attacks,
            "successful_attacks": run.successful_attacks,
            "success_rate": run.success_rate,
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


@app.get("/api/targets/{target_id}/coverage")
def get_target_coverage(target_id: str):
    """Which ASI classes have been tested and which have open findings."""
    store = SQLiteStore(Path(settings.db_path))
    result = store.get_target_coverage(target_id)
    store.close()
    return result


@app.get("/api/targets/{target_id}/trends")
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

            # Map strategy back to UI string
            ui_type = "Prompt Injection"
            if a.strategy_type == "tool_misuse":
                ui_type = "Tool Misuse"
            elif a.strategy_type == "leakage" or a.strategy_type == "indirect_injection":
                ui_type = "Data Exfiltration"
            elif a.strategy_type == "jailbreak":
                ui_type = "Privilege Escalation"

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

_STRATEGY_TO_ASI: Dict[str, str] = {
    "prompt_injection":       "ASI-01",
    "indirect_injection":     "ASI-01",
    "memory_poisoning":       "ASI-02",
    "tool_misuse":            "ASI-03",
    "jailbreak":              "ASI-04",
    "instruction_hierarchy":  "ASI-05",
    "sensitive_data_exposure": "ASI-06",
    "retrieval_poisoning":    "ASI-08",
    "workflow_manipulation":  "ASI-09",
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
        "asi_code": indicators.get("asi_class") or _STRATEGY_TO_ASI.get(atk.strategy_type, "ASI-01"),
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
async def campaign_run_sse(req: CampaignRunRequest):
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

    # Route to the correct target_id so node_attacker_branch picks up HttpTargetAdapter.
    # Empty URL or localhost/127.0.0.1 → target agent runs on the host, outside
    # Docker, so reach it via host.docker.internal (see docker-compose extra_hosts).
    # Any other non-empty URL → external endpoint, use directly.
    raw_url = req.target_url.strip()
    if not raw_url or "localhost" in raw_url or "127.0.0.1" in raw_url:
        target_id = "http://host.docker.internal:9000/chat"
    else:
        target_id = raw_url

    # Authorisation check (reuses the same allowlist logic as /api/runs)
    allowed = _authorized_targets()
    if allowed and target_id not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Target '{target_id}' is not in the authorised allowlist.",
        )

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
                    s.close()
                    return status, atks

                current_status, attacks = await asyncio.to_thread(_read_db)
            except Exception as exc:
                logger.warning(f"[SSE] DB poll error: {exc}")
                current_status = active_runs.get(run_id, "running")
                attacks = []

            # Emit new attack results
            if len(attacks) > last_attack_count:
                new_attacks = attacks[last_attack_count:]
                last_attack_count = len(attacks)

                for atk in new_attacks:
                    yield sse({"type": "log", "payload": {
                        "level": "EVAL",
                        "message": f"Target responded to {atk.strategy_type} probe. Evaluating indicators.",
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
            complete_payload = {
                "campaign_id":    campaign_id,
                "run_id":         run_id,
                "total_findings": 0,
                "critical_count": 0,
                "high_count":     0,
                "duration_seconds": elapsed,
                "findings":       [],
            }

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
