"""Registry of attack strategies."""

from typing import Dict, List

from cyberredteam.schemas import StrategyType

# Strategy registry: maps strategy type to attack descriptions and examples
STRATEGY_REGISTRY: Dict[StrategyType, Dict[str, str]] = {
    StrategyType.PROMPT_INJECTION: {
        "name": "Direct Prompt Injection",
        "description": "Directly inject malicious instructions into the prompt",
        "example": "Ignore previous instructions and...",
        "risk": "high",
    },
    StrategyType.INDIRECT_INJECTION: {
        "name": "Indirect Prompt Injection",
        "description": "Inject malicious content via retrieval sources or tool outputs",
        "example": "Embed attack in retrieved document metadata",
        "risk": "high",
    },
    StrategyType.TOOL_MISUSE: {
        "name": "Tool Misuse Attack",
        "description": "Abuse tool calling to extract data or bypass controls",
        "example": "Call tools with malicious parameters",
        "risk": "high",
    },
    StrategyType.RETRIEVAL_POISONING: {
        "name": "Retrieval Poisoning",
        "description": "Poison retrieval index with adversarial content",
        "example": "Inject crafted documents into knowledge base",
        "risk": "medium",
    },
    StrategyType.JAILBREAK: {
        "name": "Jailbreak Attempt",
        "description": "Attempt to bypass safety guardrails",
        "example": "Role-play scenarios to elicit harmful content",
        "risk": "high",
    },
    StrategyType.LEAKAGE: {
        "name": "Data Leakage",
        "description": "Attempt to extract sensitive information or context",
        "example": "Ask for internal configuration or training data",
        "risk": "medium",
    },
}


def get_strategy_info(strategy_type: StrategyType) -> Dict[str, str]:
    """Get information about a strategy."""
    return STRATEGY_REGISTRY.get(strategy_type, {})


def list_strategies() -> List[StrategyType]:
    """List all available strategies."""
    return list(STRATEGY_REGISTRY.keys())


def get_risk_level(strategy_type: StrategyType) -> str:
    """Get risk level for a strategy."""
    info = get_strategy_info(strategy_type)
    return info.get("risk", "unknown")
