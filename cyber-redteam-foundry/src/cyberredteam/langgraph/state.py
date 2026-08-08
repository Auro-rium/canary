"""RedTeam state definition for LangGraph.

Strongly typed state with Annotated append-only lists for proper
delta-based updates in LangGraph nodes.
"""

import operator
from typing import Dict, List, Optional

from typing_extensions import Annotated, TypedDict

from cyberredteam.schemas import AttackResult


class RedTeamState(TypedDict):
    """State for the red team LangGraph workflow.

    Fields use ``Annotated[list, operator.add]`` where nodes should
    *append* items rather than replace the full list.  This lets each
    node return only a delta dict and LangGraph merges it automatically.
    """

    # ── Run metadata ─────────────────────────────────────────────
    run_id: str
    target_id: str
    description: str
    seed: Optional[int]
    status: str  # "running" | "completed" | "failed"

    # ── Generic HTTP target config ───────────────────────────────
    target_headers: Dict[str, str]
    target_request_template: Optional[str]
    target_response_path: Optional[str]
    replay_cases: List[Dict[str, str]]

    # ── Attack configuration ─────────────────────────────────────
    strategies: List[str]
    max_iterations: int
    max_attempts_per_strategy: int
    timeout_seconds: int

    # ── Execution tracking (append-only via Annotated) ───────────
    iteration: int
    current_strategy: str
    attack_results: Annotated[List[AttackResult], operator.add]

    # ── Routing flags ────────────────────────────────────────────
    should_continue_iterating: bool
    vulnerability_found: bool

    # ── Aggregate scores from evaluator ──────────────────────────
    scores: Dict[str, float]

    # ── Report outputs ───────────────────────────────────────────
    report_paths: Dict[str, str]
    graph_visualization: str

    # ── Timing & errors ──────────────────────────────────────────
    start_time: Optional[float]
    end_time: Optional[float]
    error: Optional[str]

    # ── Structured log (append-only) ─────────────────────────────
    log_messages: Annotated[List[str], operator.add]
