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

    strategies: List[str] = Field(
        ...,
        description=(
            "Selected attack strategy identifiers from the registry. "
            "Values: prompt_injection, indirect_injection, tool_misuse, "
            "retrieval_poisoning, jailbreak, leakage"
        ),
    )
    rationale: str = Field(
        ...,
        description="Explanation of why these strategies were selected",
    )
    priority: str = Field(
        ...,
        description="Priority ordering rationale (e.g. 'high-risk first')",
    )


# ─── Attacker ────────────────────────────────────────────────────────

class AttackCase(BaseModel):
    """A single generated attack test case."""

    attack_type: str = Field(
        ...,
        description="Type of attack (e.g. prompt_injection, jailbreak)",
    )
    objective: str = Field(
        ...,
        description="What the attack aims to achieve",
    )
    generated_test_case: str = Field(
        ...,
        description="The actual adversarial prompt to send to the target",
    )
    expected_failure: str = Field(
        ...,
        description="What a successful exploit would look like",
    )
    severity_guess: str = Field(
        default="medium",
        description="Estimated severity: critical, high, medium, low, info",
    )


# ─── Evaluator ───────────────────────────────────────────────────────

class EvaluationResult(BaseModel):
    """LLM judge evaluation of a single attack–response pair."""

    success: bool = Field(
        ...,
        description="Whether the attack was successful",
    )
    severity: str = Field(
        ...,
        description="Severity level: critical, high, medium, low, info",
    )
    vulnerability_type: str = Field(
        ...,
        description="Type of vulnerability observed",
    )
    explanation: str = Field(
        ...,
        description="Detailed explanation of the assessment",
    )
    evidence: str = Field(
        default="",
        description="Specific text or behavior used as evidence",
    )


# ─── Defender ────────────────────────────────────────────────────────

class DefensePatch(BaseModel):
    """LLM-proposed remediation for a vulnerability."""

    patch_type: str = Field(
        ...,
        description=(
            "Patch category: system_prompt_update, tool_permission_change, "
            "retrieval_filter_change, memory_policy_change, guardrail_update"
        ),
    )
    description: str = Field(
        ...,
        description="What the patch does",
    )
    affected_component: str = Field(
        ...,
        description="Which component this patch targets",
    )
    expected_improvement: str = Field(
        ...,
        description="Expected impact of applying this patch",
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
