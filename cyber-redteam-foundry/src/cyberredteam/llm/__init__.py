"""LLM abstraction layer routed through Backboard.io.

Provides per-agent model factories and structured output support.
"""

from cyberredteam.llm.factory import get_llm, get_llm_for_agent
from cyberredteam.llm.observable import ObservableLLM
from cyberredteam.llm.schemas import (
    AttackerOutput,
    AttackPlan,
    EvaluationResult,
    SecurityReport,
)

__all__ = [
    "get_llm",
    "get_llm_for_agent",
    "ObservableLLM",
    "AttackPlan",
    "AttackerOutput",
    "EvaluationResult",
    "SecurityReport",
]
