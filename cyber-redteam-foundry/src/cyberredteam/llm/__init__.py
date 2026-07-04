"""LLM abstraction layer for AWS Bedrock (Claude).

Provides per-agent model factories and structured output support.
"""

from cyberredteam.llm.factory import get_llm, get_llm_for_agent
from cyberredteam.llm.schemas import (
    AttackerOutput,
    AttackPlan,
    EvaluationResult,
    SecurityReport,
)

__all__ = [
    "get_llm",
    "get_llm_for_agent",
    "AttackPlan",
    "AttackerOutput",
    "EvaluationResult",
    "SecurityReport",
]
