"""Pydantic schemas for the red team framework."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class StrategyType(str, Enum):
    """Attack strategy types."""

    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    TOOL_MISUSE = "tool_misuse"
    RETRIEVAL_POISONING = "retrieval_poisoning"
    JAILBREAK = "jailbreak"
    LEAKAGE = "leakage"


class AttackSeverity(str, Enum):
    """Attack severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PatchType(str, Enum):
    """Defense patch types."""

    PROMPT_HARDENING = "prompt_hardening"
    TOOL_POLICY = "tool_policy"
    RETRIEVAL_FILTER = "retrieval_filter"
    MEMORY_ISOLATION = "memory_isolation"
    REGRESSION_RULE = "regression_rule"


class RunConfig(BaseModel):
    """Configuration for a red team run."""

    run_id: str
    target_id: str
    strategy_types: List[StrategyType] = Field(default_factory=list)
    max_attempts: int = 5
    timeout_seconds: int = 30
    seed: Optional[int] = None
    description: str = ""


class AttackPrompt(BaseModel):
    """A prompt to be used in an attack."""

    prompt_id: str
    strategy_type: StrategyType
    content: str
    risk_level: str = "medium"
    description: str = ""


class AttackResult(BaseModel):
    """Result of an attack attempt."""

    run_id: str
    attempt_number: int
    strategy_type: StrategyType
    prompt: str
    response: str
    success: bool
    severity: AttackSeverity
    score: float = Field(ge=0.0, le=1.0)
    indicators: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None


class PatchResult(BaseModel):
    """Result of a defensive patch."""

    run_id: str
    patch_id: str
    patch_type: PatchType
    target_component: str
    original_config: Dict[str, Any]
    patched_config: Dict[str, Any]
    diff: str
    applied: bool
    retest_passed: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class RedTeamReport(BaseModel):
    """Final red team report."""

    run_id: str
    target_id: str
    start_time: datetime
    end_time: datetime
    total_attacks: int
    successful_attacks: int
    attack_results: List[AttackResult]
    patches_applied: List[PatchResult]
    severity_distribution: Dict[AttackSeverity, int]
    success_rate: float = Field(ge=0.0, le=1.0)
    recommendations: List[str]
    assumptions: List[str]
    evidence_files: Dict[str, str] = Field(default_factory=dict)
    narratives: Dict[str, str] = Field(default_factory=dict)
