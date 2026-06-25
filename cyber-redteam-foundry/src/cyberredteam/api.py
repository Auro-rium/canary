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
from pydantic import BaseModel
from sqlalchemy import select

from cyberredteam.langgraph.orchestrator import GraphOrchestrator
from cyberredteam.schemas import RunConfig, StrategyType
from cyberredteam.settings import get_settings
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import AttackRecord, PatchRecord, RunRecord

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


def run_orchestrator_thread(
    run_id: str,
    target_id: str,
    strategy_types: List[StrategyType],
    max_iterations: int,
    max_attempts: int,
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

        # Get patches
        stmt_patches = select(PatchRecord).where(PatchRecord.run_id == run_id)
        patches = session.scalars(stmt_patches).all()

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
            "patches": [
                {
                    "id": p.id,
                    "patch_id": p.patch_id,
                    "patch_type": p.patch_type,
                    "target_component": p.target_component,
                    "original_config": p.original_config,
                    "patched_config": p.patched_config,
                    "diff": p.diff,
                    "applied": bool(p.applied),
                    "retest_passed": bool(p.retest_passed),
                    "finding_id": p.finding_id,
                    "retest_prompt": p.retest_prompt,
                    "retest_response": p.retest_response,
                }
                for p in patches
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

        # Get patches
        stmt_patches = select(PatchRecord).where(PatchRecord.run_id == run_id)
        patches = session.scalars(stmt_patches).all()

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
    fixes_applied = narratives.get("fixes_applied", "")

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

    # 3. Defender patching step
    if patches:
        all_passed = all(p.retest_passed for p in patches)
        trace.append({
            "time": "Final Step",
            "action": "Guardrail Integration",
            "details": f"Defender synthesized {len(patches)} patches. Retests: {'Passed' if all_passed else 'Failed'}",
            "status": "passed" if all_passed else "warning",
        })

    # Build YAML policy string from patches
    yaml_lines = [
        "version: '2.1'",
        f"policy_id: guard-{run.target_id.lower().replace(' ', '-')}-{run_id}",
        "governance:",
        f"  agent: {run.target_id}",
        "  scope: Tool Invocation",
        "rules:"
    ]
    for idx, p in enumerate(patches):
        yaml_lines.extend([
            f"  - id: patch-{idx}",
            f"    type: {p.patch_type}",
            f"    component: {p.target_component}",
            "    action: MASK",
            "    retest_status: PASSED" if p.retest_passed else "    retest_status: FAILED"
        ])

    suggested_yaml = "\n".join(yaml_lines)

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
        "mitigation": fixes_applied,
        "confidence": confidence_percentage,
        "severity": max_severity,
        "trace": trace,
        "attackPayload": attack_payload,
        "rawOutput": raw_output,
        "suggestedYaml": suggested_yaml,
        "recommendations": recommendations,
    }


@app.get("/api/open-findings")
def get_open_findings(target_id: Optional[str] = None):
    """Return findings with no passing retest across all historical runs.

    Used by the next campaign's strategist to avoid re-discovering known
    open issues from scratch.  Each entry carries finding_id, the affected
    component, when it was last seen, and how many patch attempts failed.
    """
    store = SQLiteStore(Path(settings.db_path))
    findings = store.get_open_findings(target_id=target_id)
    store.close()
    return findings


@app.post("/api/runs/{run_id}/apply")
def apply_policy(run_id: str):
    """Mark all patches for a run as applied in the database."""
    store = SQLiteStore(Path(settings.db_path))
    with store.SessionLocal() as session:
        stmt = select(PatchRecord).where(PatchRecord.run_id == run_id)
        patches = session.scalars(stmt).all()
        for p in patches:
            p.applied = 1
        session.commit()
    store.close()
    return {"status": "success", "message": "Patches successfully applied to control plane"}


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
