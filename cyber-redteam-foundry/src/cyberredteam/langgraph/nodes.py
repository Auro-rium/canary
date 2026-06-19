"""LangGraph node implementations for the red team workflow.

Each node function receives the full ``RedTeamState`` and returns
**only the keys it wants to update** (a delta dict).  For fields
annotated with ``Annotated[list, operator.add]`` (e.g.
``attack_results``, ``patch_results``, ``log_messages``), the returned
list is *appended* to the existing state rather than replacing it.

Agent instances are created via a factory so they can be injected in
tests.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional

from cyberredteam.agents.attacker import AttackerAgent
from cyberredteam.agents.defender import DefenderAgent
from cyberredteam.agents.evaluator import EvaluatorAgent
from cyberredteam.agents.reporter import ReporterAgent
from cyberredteam.agents.strategist import StrategistAgent
from cyberredteam.langgraph.state import RedTeamState
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import StrategyType
from cyberredteam.settings import get_settings
from cyberredteam.storage.artifact_store import SQLiteStore

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

def _strategist_factory(**kwargs) -> StrategistAgent:
    return StrategistAgent(**kwargs)
def _attacker_factory(**kwargs) -> AttackerAgent:
    return AttackerAgent(**kwargs)
def _evaluator_factory(**kwargs) -> EvaluatorAgent:
    return EvaluatorAgent(**kwargs)
def _defender_factory(**kwargs) -> DefenderAgent:
    return DefenderAgent(**kwargs)
_reporter_factory: Optional[Callable[..., ReporterAgent]] = None


def set_strategist_factory(factory: Callable[[], StrategistAgent]) -> None:
    global _strategist_factory
    _strategist_factory = factory


def set_attacker_factory(factory: Callable[[], AttackerAgent]) -> None:
    global _attacker_factory
    _attacker_factory = factory


def set_evaluator_factory(factory: Callable[[], EvaluatorAgent]) -> None:
    global _evaluator_factory
    _evaluator_factory = factory


def set_defender_factory(factory: Callable[[], DefenderAgent]) -> None:
    global _defender_factory
    _defender_factory = factory


def set_reporter_factory(factory: Callable[..., ReporterAgent]) -> None:
    global _reporter_factory
    _reporter_factory = factory


# ---------------------------------------------------------------------------
# Node: strategist
# ---------------------------------------------------------------------------

def node_strategist(state: RedTeamState) -> dict:
    """Select attack strategies based on target and risk appetite.

    Returns delta with ``strategies`` and a log message.
    """
    logger.info(f"[Graph] Strategist node — Run {state['run_id']}")

    # Extract previous vulnerabilities from successful attacks
    prev_results = state.get("attack_results", [])
    successful = [r for r in prev_results if r.success]
    previous_vulnerabilities = list(set(r.strategy_type.value for r in successful))

    strategist = _strategist_factory(store=get_node_store())
    strategies = strategist.select_strategies(
        target_id=state["target_id"],
        risk_appetite="medium",
        count=min(3, len(state["strategies"])),
        previous_vulnerabilities=previous_vulnerabilities,
        available_subset=state["strategies"],
    )

    selected = [s.value for s in strategies]
    logger.info(f"[Graph] Strategist selected: {selected}")

    return {
        "strategies": selected,
        "log_messages": [f"Strategist selected {len(selected)} strategies: {selected}"],
    }


# ---------------------------------------------------------------------------
# Node: attacker
# ---------------------------------------------------------------------------

def node_attacker(state: RedTeamState) -> dict:
    """Execute attacks for all strategies in this iteration.

    Returns delta that *appends* to ``attack_results`` and
    ``log_messages``.
    """
    iteration = state["iteration"]
    logger.info(
        f"[Graph] Attacker node — Run {state['run_id']}, "
        f"Iteration {iteration}"
    )
    # Auto-detect HTTP target endpoints
    target_id = state["target_id"]
    target_adapter = None
    if target_id.startswith("http://") or target_id.startswith("https://"):
        from cyberredteam.tools.target_adapter import HttpTargetAdapter
        target_adapter = HttpTargetAdapter(endpoint=target_id)
        logger.info(f"[Graph] Attacker using HTTP target adapter → {target_id}")

    attacker = _attacker_factory(
        store=get_node_store(),
        **({"target_adapter": target_adapter} if target_adapter else {}),
    )

    strategy_list = [StrategyType(s) for s in state["strategies"]]

    results = attacker.batch_attack(
        run_id=state["run_id"],
        target_id=state["target_id"],
        strategies=strategy_list,
        max_attempts_per_strategy=state["max_attempts_per_strategy"],
        previous_attempts=state.get("attack_results", []),
        known_defenses=state.get("patch_results", []),
    )

    current_strategy = results[0].strategy_type.value if results else ""

    logger.info(f"[Graph] Attacker executed {len(results)} attacks")

    return {
        "attack_results": results,  # appended via Annotated
        "current_strategy": current_strategy,
        "log_messages": [
            f"Attacker executed {len(results)} attacks (iteration {iteration})"
        ],
    }


# ---------------------------------------------------------------------------
# Node: evaluator
# ---------------------------------------------------------------------------

def node_evaluator(state: RedTeamState) -> dict:
    """Evaluate the most recent batch of attack results.

    Sets routing flags: ``vulnerability_found``, ``should_patch``,
    ``should_continue_iterating``.
    """
    logger.info(f"[Graph] Evaluator node — Run {state['run_id']}")

    evaluator = _evaluator_factory(store=get_node_store())

    # Evaluate the most recent batch (last N results where N = strategies × attempts)
    batch_size = (
        len(state["strategies"]) * state["max_attempts_per_strategy"]
    )
    recent = state["attack_results"][-batch_size:] if state["attack_results"] else []

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

    # Should we keep iterating?
    can_iterate = state["iteration"] < state["max_iterations"] and vuln_found

    logger.info(
        f"[Graph] Evaluator: {len(successful)} successful attacks, "
        f"vulnerability_found={vuln_found}, can_iterate={can_iterate}"
    )

    return {
        "vulnerability_found": vuln_found,
        "should_patch": vuln_found,
        "should_continue_iterating": can_iterate,
        "scores": scores,
        "log_messages": [
            f"Evaluator: {len(successful)} successful attacks found, "
            f"vulnerability_found={vuln_found}"
        ],
    }


# ---------------------------------------------------------------------------
# Node: defender
# ---------------------------------------------------------------------------

def node_defender(state: RedTeamState) -> dict:
    """Plan, apply, and retest patches for successful attacks.

    Increments ``iteration`` and recalculates
    ``should_continue_iterating``.
    """
    logger.info(f"[Graph] Defender node — Run {state['run_id']}")

    defender = _defender_factory(store=get_node_store())

    successful = [r for r in state["attack_results"] if r.success]
    if not successful:
        logger.info("[Graph] Defender: nothing to patch")
        return {
            "log_messages": ["Defender: no successful attacks to patch"],
        }

    # Plan → apply → retest
    patches = defender.plan_defenses(successful)
    applied = defender.apply_patches(patches)

    for patch in applied:
        prompts = [r.prompt for r in successful]
        defender.retest_after_patch(patch, prompts)

    new_iteration = state["iteration"] + 1
    can_continue = (
        new_iteration < state["max_iterations"]
        and any(p.retest_passed for p in applied)
    )

    logger.info(
        f"[Graph] Defender applied {len(applied)} patches, "
        f"iteration={new_iteration}, continue={can_continue}"
    )

    return {
        "patch_results": applied,  # appended via Annotated
        "iteration": new_iteration,
        "should_continue_iterating": can_continue,
        "log_messages": [
            f"Defender applied {len(applied)} patches (iteration {new_iteration})"
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
        patches=state["patch_results"],
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
