"""Agents module initialization.

Note: CoordinatorAgent has been removed.  Orchestration is now handled
entirely by the LangGraph StateGraph in ``cyberredteam.langgraph``.
"""

from cyberredteam.agents.attacker import AttackerAgent
from cyberredteam.agents.defender import DefenderAgent
from cyberredteam.agents.evaluator import EvaluatorAgent
from cyberredteam.agents.reporter import ReporterAgent
from cyberredteam.agents.strategist import StrategistAgent

__all__ = [
    "StrategistAgent",
    "AttackerAgent",
    "EvaluatorAgent",
    "DefenderAgent",
    "ReporterAgent",
]
