"""Pydantic schemas for the red team framework."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class StrategyType(str, Enum):
    """Attack strategy types."""

    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    TOOL_MISUSE = "tool_misuse"
    RETRIEVAL_POISONING = "retrieval_poisoning"
    MEMORY_POISONING = "memory_poisoning"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    WORKFLOW_MANIPULATION = "workflow_manipulation"
    AGENT_HANDOFF_CORRUPTION = "agent_handoff_corruption"
    AUTHORIZATION_BOUNDARY = "authorization_boundary"
    INSTRUCTION_HIERARCHY = "instruction_hierarchy"
    CONTEXT_ISOLATION = "context_isolation"
    PRIVILEGE_ESCALATION = "privilege_escalation"



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
    # Generic HTTP target config — lets the run attack any HTTP JSON agent,
    # not just the bundled target_agent stub's {"message": ...} contract.
    target_headers: Dict[str, str] = Field(default_factory=dict)
    target_request_template: Optional[str] = None
    target_response_path: Optional[str] = None


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
    target_id: str = Field(default="")
    attempt_number: int
    strategy_type: StrategyType
    prompt: str
    response: str
    success: bool
    severity: AttackSeverity
    score: float = Field(ge=0.0, le=1.0)
    # Threshold applied to LLM confidence to determine success. Stored so every
    # verdict is reproducible: auditor sees score, confidence, and the cutoff.
    score_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    # Content-addressed ID stable across runs: sha256(strategy+target+component)[:12].
    # Minted by the defender once affected_component is known; empty until then.
    finding_id: str = Field(default="")
    indicators: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None

    # ── Parallel fan-out branch metadata (added for the multi-branch attacker) ──
    # All default to empty/0 so existing single-branch-shaped results stay valid.
    technique_id: str = Field(default="", description="ASI-class technique id (e.g. ASI04)")
    capability_type: str = Field(default="", description="Same as strategy_type.value")
    depth: int = Field(default=0, description="0 = first attempt on this branch")
    mutation_of_parent: Optional[str] = Field(default=None)
    branch_id: str = Field(default="", description="uuid4 hex tagging this branch's attempts")
    iteration: int = Field(default=0, description="Graph iteration this result was produced in")


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
    # Links this patch back to the finding it addresses — same ID as the source
    # AttackResult.finding_id so open issues are queryable across campaigns.
    finding_id: str = Field(default="")
    # Verbatim replay evidence from the retest: the exact prompt and response
    # that determined retest_passed. Required for verified_fixed to be earnable.
    retest_prompt: str = Field(default="")
    retest_response: str = Field(default="")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


@dataclass
class AttackBranch:
    """One parallel attacker branch: one technique, one depth/budget lineage.

    Carried through LangGraph Send() payloads, deliberately NOT part of
    RedTeamState — each parallel branch needs an independent depth/budget
    countdown, which doesn't merge cleanly via Annotated[list, operator.add]
    reducer semantics. Only the branch's output (an AttackResult) rejoins
    shared state. A resumed run re-derives branch context from attack_results
    history (tagged by branch_id/technique_id) rather than needing this to
    survive checkpointing on its own.
    """

    branch_id: str
    capability_type: str
    technique_id: str
    technique_spec: str
    target_metadata: Dict[str, Any] = field(default_factory=dict)
    depth: int = 0
    attempt_budget_remaining: int = 3
    parent_evidence: Optional[Dict[str, Any]] = None


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
