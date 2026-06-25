"""Structured output schemas for LLM-powered agents.

These Pydantic models are used with ``llm.with_structured_output()``
to guarantee well-typed JSON from every LLM call.  Free-form text
is never parsed directly.
"""

from typing import List

from pydantic import BaseModel, Field

# ─── Strategist ──────────────────────────────────────────────────────

class AttackPlan(BaseModel):
    """Output of the strategist agent."""

    categories: List[str] = Field(
        ...,
        description="Selected evaluation category identifiers from the registry.",
    )
    priorities: List[str] = Field(
        ...,
        description="Priorities for each selected category.",
    )
    rationale: str = Field(
        ...,
        description="Explanation of why these strategies were selected",
    )


# ─── Attacker ────────────────────────────────────────────────────────

class AttackCase(BaseModel):
    """A single generated attack test case."""

    category: str = Field(
        ...,
        description="Type of attack/evaluation category",
    )
    scenario_description: str = Field(
        ...,
        description="Description of the test scenario",
    )
    evaluation_prompt: str = Field(
        ...,
        description="The actual adversarial evaluation prompt to send to the target",
    )
    expected_safe_behavior: str = Field(
        ...,
        description="The expected safe behavior of the target under this test case",
    )
    failure_condition: str = Field(
        ...,
        description="What a boundary failure/exploit would look like in the response",
    )


# ─── Evaluator ───────────────────────────────────────────────────────

class EvaluationResult(BaseModel):
    """LLM judge evaluation of a single attack–response pair."""

    boundary_failure: bool = Field(
        ...,
        description="Whether a safety boundary failure was detected",
    )
    severity: str = Field(
        ...,
        description="Severity level: critical, high, medium, low, info",
    )
    finding: str = Field(
        ...,
        description="Detailed explanation of the assessment findings",
    )
    evidence: str = Field(
        default="",
        description="Specific text or behavior used as evidence of success or failure",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in the evaluation result (0.0-1.0)",
    )


# ─── Defender ────────────────────────────────────────────────────────

class DefensePatch(BaseModel):
    """LLM-proposed remediation for a vulnerability."""

    patch_type: str = Field(
        ...,
        description="Patch category/type",
    )
    affected_component: str = Field(
        ...,
        description="Which component this patch targets",
    )
    recommendation: str = Field(
        ...,
        description="The mitigation recommendation (e.g. system prompt guidelines)",
    )
    expected_risk_reduction: str = Field(
        ...,
        description="Expected reduction in risk/improvement",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence that this patch will be effective (0.0-1.0)",
    )


# ─── Reporter ────────────────────────────────────────────────────────

class SecurityReport(BaseModel):
    """LLM-generated narrative sections for the final report."""

    executive_summary: str = Field(
        ...,
        description="High-level summary of findings and risk level",
    )
    attack_campaign: str = Field(
        ...,
        description="Description of the attack campaign and approach",
    )
    vulnerabilities_found: str = Field(
        ...,
        description="Detailed description of vulnerabilities discovered",
    )
    evidence_summary: str = Field(
        ...,
        description="Summary of evidence supporting findings",
    )
    fixes_applied: str = Field(
        ...,
        description="Description of patches applied and their effectiveness",
    )
    regression_results: str = Field(
        ...,
        description="Results of retesting after patches",
    )
    remaining_risks: str = Field(
        ...,
        description="Risks that remain after patching",
    )
    assumptions: str = Field(
        ...,
        description="Assumptions and scope limitations",
    )
