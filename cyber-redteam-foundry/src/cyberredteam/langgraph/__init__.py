"""LangGraph-based orchestration for red team workflows.

This package is the **primary** orchestration layer.  The legacy
``cyberredteam.orchestrator`` package is deprecated.
"""

from cyberredteam.langgraph.graph import (
    build_redteam_graph,
    compile_graph,
    get_mermaid_graph,
)
from cyberredteam.langgraph.orchestrator import GraphOrchestrator
from cyberredteam.langgraph.state import RedTeamState

__all__ = [
    "build_redteam_graph",
    "compile_graph",
    "get_mermaid_graph",
    "GraphOrchestrator",
    "RedTeamState",
]
