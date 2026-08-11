"""LangGraph state graph builder for the red team workflow.

Builds a ``StateGraph[RedTeamState]`` with:

*  4 nodes: strategist → attacker_branch (parallel fan-out) → evaluator → reporter
*  strategist dispatches the requested parallel attacker_branch invocations via Send(),
   preserving the requested technique order — LangGraph waits for all of them before evaluator runs
*  Iterative loop, owned entirely by evaluator: evaluator → (strategist, to re-dispatch a
   fresh branch set, if vulnerability_found and iterations remain, else reporter)
*  SQLite-backed checkpointing for persistence and resumability
*  Auto-generated Mermaid diagram
"""

from typing import Literal, Optional

from langgraph.graph import END, StateGraph

from cyberredteam.langgraph.nodes import (
    dispatch_attacker_branches,
    node_attacker_branch,
    node_evaluator,
    node_reporter,
    node_strategist,
)
from cyberredteam.langgraph.state import RedTeamState
from cyberredteam.logging import setup_logging

logger = setup_logging()


# ---------------------------------------------------------------------------
# Conditional routing functions
# ---------------------------------------------------------------------------

def should_iterate(state: RedTeamState) -> Literal["strategist", "reporter"]:
    """Route back to strategist (to re-dispatch a fresh branch set) if
    a vulnerability was found and iterations remain, else to reporter.

    Args:
        state: Current RedTeamState

    Returns:
        Next node: ``"strategist"`` or ``"reporter"``
    """
    logger.info(
        f"[Graph] Routing after evaluator: "
        f"should_continue={state['should_continue_iterating']}, "
        f"iteration={state['iteration']}/{state['max_iterations']}"
    )
    return "strategist" if state["should_continue_iterating"] else "reporter"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_redteam_graph() -> StateGraph:
    """Build the red team workflow graph (uncompiled).

    Returns:
        ``StateGraph`` ready for ``.compile()``.
    """
    graph = StateGraph(RedTeamState)

    # Add nodes
    graph.add_node("strategist", node_strategist)
    graph.add_node("attacker_branch", node_attacker_branch)
    graph.add_node("evaluator", node_evaluator)
    graph.add_node("reporter", node_reporter)

    # Entry point
    graph.set_entry_point("strategist")

    # Parallel fan-out: strategist → up to 3 concurrent attacker_branch invocations,
    # preserving requested technique order. LangGraph waits for all Send-spawned
    # branches to complete before evaluator runs (superstep boundary) — no manual
    # join/barrier logic needed.
    graph.add_conditional_edges("strategist", dispatch_attacker_branches)
    graph.add_edge("attacker_branch", "evaluator")

    # Iterative loop, owned entirely by evaluator: strategist (re-dispatch a
    # fresh parallel branch set) if a vulnerability was found and iterations
    # remain, else reporter.
    graph.add_conditional_edges(
        "evaluator",
        should_iterate,
        {
            "strategist": "strategist",
            "reporter": "reporter",
        },
    )

    # Terminal
    graph.add_edge("reporter", END)

    logger.info("Built RedTeam LangGraph state machine")
    return graph


# ---------------------------------------------------------------------------
# Compilation helpers
# ---------------------------------------------------------------------------

def compile_graph(checkpoint_db_path: Optional[str] = None):
    """Compile the graph with SQLite checkpointing.

    Args:
        checkpoint_db_path: Path to an SQLite file for checkpoints.
            If ``None``, falls back to in-memory ``MemorySaver``.

    Returns:
        Compiled graph ready for ``.invoke()`` / ``.stream()``.
    """
    graph = build_redteam_graph()

    if checkpoint_db_path:
        import sqlite3

        from langgraph.checkpoint.sqlite import SqliteSaver

        conn = sqlite3.connect(checkpoint_db_path, check_same_thread=False)
        checkpointer = SqliteSaver(conn)
        logger.info(
            f"Compiled RedTeam graph with SQLite checkpointing → "
            f"{checkpoint_db_path}"
        )
    else:
        from langgraph.checkpoint.memory import MemorySaver

        checkpointer = MemorySaver()
        logger.info("Compiled RedTeam graph with in-memory checkpointing")

    compiled = graph.compile(checkpointer=checkpointer)
    return compiled


def get_mermaid_graph(checkpoint_db_path: Optional[str] = None) -> str:
    """Generate Mermaid diagram of the compiled graph.

    Attempts auto-generation via LangGraph's ``draw_mermaid()`` API.
    Falls back to a hand-crafted diagram if the API is unavailable.

    Returns:
        Mermaid diagram string.
    """
    try:
        compiled = compile_graph(checkpoint_db_path)
        mermaid = compiled.get_graph().draw_mermaid()
        logger.info("Generated Mermaid diagram via LangGraph API")
        return mermaid
    except Exception as exc:
        logger.warning(
            f"Auto-generated Mermaid failed ({exc}), using fallback diagram"
        )
        return _fallback_mermaid()


def _fallback_mermaid() -> str:
    """Hand-crafted Mermaid diagram as fallback."""
    return """\
graph TD
    START([START])
    strategist["<b>Strategist</b><br/>Dispatch requested techniques"]
    attacker_branch["<b>Attacker Branch</b><br/>Execute one attack (parallel)"]
    evaluator["<b>Evaluator</b><br/>Score & assess"]
    reporter["<b>Reporter</b><br/>Generate report"]
    END_NODE([END])

    START --> strategist
    strategist -.->|Send xN, deterministic| attacker_branch
    attacker_branch --> evaluator

    evaluator -->|vulnerability_found & iterations remain| strategist
    evaluator -->|done| reporter

    reporter --> END_NODE

    style START fill:#90EE90
    style END_NODE fill:#FFB6C6
    style strategist fill:#87CEEB
    style attacker_branch fill:#87CEEB
    style evaluator fill:#87CEEB
    style reporter fill:#DDA0DD
"""
