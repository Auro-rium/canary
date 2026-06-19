"""Orchestrator module — DEPRECATED.

This module is deprecated.  Orchestration is now handled by the
LangGraph StateGraph in ``cyberredteam.langgraph``.

The legacy ``RedTeamOrchestrator``, ``StateMachine``, and ``RunState``
are preserved here only for backward compatibility.  They will be
removed in a future release.
"""

import warnings

from cyberredteam.orchestrator.runner import RedTeamOrchestrator
from cyberredteam.orchestrator.state_machine import RunState, StateMachine

warnings.warn(
    "cyberredteam.orchestrator is deprecated. "
    "Use cyberredteam.langgraph.GraphOrchestrator instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["RedTeamOrchestrator", "StateMachine", "RunState"]
