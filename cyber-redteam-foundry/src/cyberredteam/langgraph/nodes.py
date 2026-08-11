"""LangGraph node implementations for the red team workflow.

Each node function receives the full ``RedTeamState`` and returns
**only the keys it wants to update** (a delta dict).  For fields
annotated with ``Annotated[list, operator.add]`` (e.g.
``attack_results``, ``log_messages``), the returned
list is *appended* to the existing state rather than replacing it.

Agent instances are created via a factory so they can be injected in
tests.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from langgraph.types import Send

from cyberredteam.agents.attacker import AttackerAgent
from cyberredteam.agents.evaluator import EvaluatorAgent
from cyberredteam.agents.reporter import ReporterAgent
from cyberredteam.evaluation import taxonomy
from cyberredteam.evaluation.technique_specs import get_spec
from cyberredteam.langgraph.state import RedTeamState
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackBranch, StrategyType
from cyberredteam.settings import get_settings
from cyberredteam.storage.artifact_store import SQLiteStore

# Max parallel attacker branches spawned per strategist dispatch.
MAX_PARALLEL_BRANCHES = 3

logger = setup_logging()


# ---------------------------------------------------------------------------
# Agent factories — override in tests via ``set_*_factory``
# ---------------------------------------------------------------------------

_store: Optional[SQLiteStore] = None

def get_node_store() -> SQLiteStore:
    global _store
    if _store is None:
        settings = get_settings()
        _store = SQLiteStore(Path(settings.db_path))
    return _store

def _attacker_factory(**kwargs) -> AttackerAgent:
    return AttackerAgent(**kwargs)
def _evaluator_factory(**kwargs) -> EvaluatorAgent:
    return EvaluatorAgent(**kwargs)
_reporter_factory: Optional[Callable[..., ReporterAgent]] = None


def set_attacker_factory(factory: Callable[[], AttackerAgent]) -> None:
    global _attacker_factory
    _attacker_factory = factory


def set_evaluator_factory(factory: Callable[[], EvaluatorAgent]) -> None:
    global _evaluator_factory
    _evaluator_factory = factory


def set_reporter_factory(factory: Callable[..., ReporterAgent]) -> None:
    global _reporter_factory
    _reporter_factory = factory


# ---------------------------------------------------------------------------
# Node: strategist
# ---------------------------------------------------------------------------

def node_strategist(state: RedTeamState) -> dict:
    """Log-only pass-through ahead of deterministic parallel dispatch.

    Technique selection is intentionally explicit in the current graph. The
    StrategistAgent remains available for future LLM-ranked selection, but the
    graph does not claim that this node called it.
    """
    logger.info(f"[Graph] Strategist node — Run {state['run_id']}")
    candidates = state["strategies"]
    logger.info(f"[Graph] Strategist candidates for deterministic dispatch: {candidates}")

    return {
        "log_messages": [f"Strategist ready to dispatch from {len(candidates)} candidate technique(s)"],
    }


# ---------------------------------------------------------------------------
# Conditional edge: strategist → parallel attacker_branch fan-out
# ---------------------------------------------------------------------------

def dispatch_attacker_branches(state: RedTeamState) -> List[Send]:
    """Select the requested techniques in order and fan them out.

    Each selected technique becomes one independent AttackBranch (fresh
    depth=0, its own attempt budget) sent to `node_attacker_branch` as a
    parallel LangGraph branch. LangGraph waits for all Send-spawned branches
    to complete before the downstream node (evaluator) runs.
    """
    candidates = [StrategyType(s) for s in state["strategies"]]
    if not candidates:
        candidates = [StrategyType.PROMPT_INJECTION]
    # Preserve the caller's explicit technique selection. Truncation is
    # deterministic and visible in logs; random selection made the UI and
    # persisted attack records disagree about what was tested.
    chosen = candidates[:MAX_PARALLEL_BRANCHES]

    logger.info(f"[Graph] Dispatching {len(chosen)} parallel attacker branch(es): {[c.value for c in chosen]}")

    sends = []
    for strategy in chosen:
        asi_class, _ = taxonomy.lookup(strategy.value, "")
        spec = get_spec(asi_class)
        branch = AttackBranch(
            branch_id=uuid.uuid4().hex,
            capability_type=strategy.value,
            technique_id=asi_class,
            technique_spec=spec["spec"],
            target_metadata={
                "name": state["target_id"],
                "declared_purpose": state["description"],
                "observability_level": "black_box",
            },
            depth=0,
            attempt_budget_remaining=state["max_attempts_per_strategy"],
            parent_evidence=None,
        )
        sends.append(Send("attacker_branch", {
            "branch": branch,
            "run_id": state["run_id"],
            "target_id": state["target_id"],
            "iteration": state["iteration"],
            "target_headers": state.get("target_headers"),
            "target_request_template": state.get("target_request_template"),
            "target_response_path": state.get("target_response_path"),
        }))
    return sends


# ---------------------------------------------------------------------------
# Node: attacker_branch (one parallel branch — one technique, one payload)
# ---------------------------------------------------------------------------

def node_attacker_branch(payload: dict) -> dict:
    """Execute exactly one attack for one branch dispatched via Send().

    Returns delta that *appends* a single-item list to ``attack_results`` and
    ``log_messages`` — LangGraph's operator.add reducer concatenates each
    parallel branch's delta regardless of completion order.
    """
    branch: AttackBranch = payload["branch"]
    run_id = payload["run_id"]
    target_id = payload["target_id"]
    iteration = payload.get("iteration", 0)

    logger.info(
        f"[Graph] Attacker branch node — Run {run_id}, branch {branch.branch_id[:8]}, "
        f"technique {branch.capability_type}"
    )

    target_adapter = None
    if target_id.startswith("http://") or target_id.startswith("https://"):
        from cyberredteam.tools.target_adapter import HttpTargetAdapter
        from cyberredteam.settings import get_settings
        target_adapter = HttpTargetAdapter(
            endpoint=target_id,
            api_key=get_settings().target_api_key,
            headers=payload.get("target_headers"),
            request_template=payload.get("target_request_template"),
            response_path=payload.get("target_response_path"),
        )

    attacker = _attacker_factory(
        store=get_node_store(),
        **({"target_adapter": target_adapter} if target_adapter else {}),
    )

    result = attacker.attack_branch(
        branch=branch,
        run_id=run_id,
        target_id=target_id,
        iteration=iteration,
    )

    logger.info(f"[Graph] Attacker branch {branch.branch_id[:8]} complete")

    return {
        "attack_results": [result],  # appended via Annotated
        # current_strategy isn't updated here: it's a plain (non-Annotated) field
        # and up to 3 parallel branches writing it in the same superstep would
        # conflict (LangGraph's InvalidUpdateError). Not worth the added
        # complexity of an Annotated list for a purely informational field.
        "log_messages": [
            f"Attacker branch {branch.branch_id[:8]} ({branch.capability_type}) complete (iteration {iteration})"
        ],
    }


# ---------------------------------------------------------------------------
# Node: evaluator
# ---------------------------------------------------------------------------

def node_evaluator(state: RedTeamState) -> dict:
    """Evaluate the most recent batch of attack results.

    Owns the retest-loop decision directly (no defender in between anymore):
    increments ``iteration`` and sets ``should_continue_iterating``/
    ``vulnerability_found``.
    """
    logger.info(f"[Graph] Evaluator node — Run {state['run_id']}")

    evaluator = _evaluator_factory(store=get_node_store())

    # Evaluate the results produced by this iteration's parallel branches.
    # Tag-based selection (not a slice) is required once branches can complete
    # out of order — a positional "last N" slice can't be trusted under fan-out.
    recent = [r for r in state["attack_results"] if r.iteration == state["iteration"]]

    if recent:
        evaluated = evaluator.evaluate_batch(recent)
        # Replace the tail of attack_results with evaluated copies.
        # Because attack_results is append-only we can't do in-place
        # replacement in a delta.  Instead, compute aggregate scores
        # and use the evaluated results for scoring.
    else:
        evaluated = []

    # Aggregate scores
    scores: Dict[str, float] = {}
    if evaluated:
        metrics = evaluator.compute_overall_metrics(evaluated)
        scores = {k: v for k, v in metrics.items() if isinstance(v, (int, float))}

    # Check if any attack succeeded
    successful = [r for r in state["attack_results"] if r.success]
    vuln_found = len(successful) > 0

    # Should we keep iterating? Re-dispatch another round of parallel branches
    # (via strategist) while there's a confirmed vulnerability and budget left.
    new_iteration = state["iteration"] + 1
    can_iterate = new_iteration < state["max_iterations"] and vuln_found

    logger.info(
        f"[Graph] Evaluator: {len(successful)} successful attacks, "
        f"vulnerability_found={vuln_found}, can_iterate={can_iterate}"
    )

    return {
        "vulnerability_found": vuln_found,
        "should_continue_iterating": can_iterate,
        "iteration": new_iteration,
        "scores": scores,
        "log_messages": [
            f"Evaluator: {len(successful)} successful attacks found, "
            f"vulnerability_found={vuln_found}"
        ],
    }


# ---------------------------------------------------------------------------
# Node: reporter
# ---------------------------------------------------------------------------

def node_reporter(state: RedTeamState) -> dict:
    """Generate final markdown and JSON reports.

    Returns ``report_paths``, ``status``, and ``end_time``.
    """
    logger.info(f"[Graph] Reporter node — Run {state['run_id']}")

    from cyberredteam.settings import get_settings

    settings = get_settings()
    report_dir = Path(settings.report_output_dir)

    if _reporter_factory is not None:
        try:
            reporter = _reporter_factory(report_dir, store=get_node_store())
        except TypeError:
            reporter = _reporter_factory(report_dir)
    else:
        reporter = ReporterAgent(report_dir, store=get_node_store())

    start_dt = (
        datetime.fromtimestamp(state["start_time"], tz=timezone.utc)
        if state.get("start_time")
        else datetime.now(tz=timezone.utc)
    )
    end_dt = datetime.now(tz=timezone.utc)

    report = reporter.generate_report(
        run_id=state["run_id"],
        target_id=state["target_id"],
        attack_results=state["attack_results"],
        start_time=start_dt,
        end_time=end_dt,
    )

    md_file = reporter.write_markdown(report)
    json_file = reporter.write_json(report)

    logger.info(f"[Graph] Reporter generated {md_file} and {json_file}")

    return {
        "report_paths": {
            "markdown": str(md_file),
            "json": str(json_file),
        },
        "status": "completed",
        "end_time": end_dt.timestamp(),
        "log_messages": [
            f"Reporter: generated {md_file} and {json_file}"
        ],
    }
