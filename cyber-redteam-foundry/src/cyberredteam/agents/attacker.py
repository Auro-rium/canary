"""Attacker agent - generates one adversarial payload per branch and executes it."""

import json
from datetime import datetime
from typing import Optional

from cyberredteam.evaluation.technique_specs import get_spec
from cyberredteam.llm.factory import get_llm_for_agent, load_prompt
from cyberredteam.llm.schemas import AttackerOutput
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackBranch, AttackResult, AttackSeverity, StrategyType
from cyberredteam.tools.target_adapter import (
    HttpTargetAdapter,
    TargetAdapter,
)
from cyberredteam.tools.prompt_injection import PromptInjectionTool
from cyberredteam.tools.sensitive_data import SensitiveDataExtractor
from cyberredteam.tools.tool_abuse import ToolAbuseTool
from cyberredteam.tools.memory_poisoning import MemoryPoisoningTool
from cyberredteam.tools.rag_probe import RAGProbeTool
from cyberredteam.tools.jailbreak import JailbreakTool
from cyberredteam.tools.instruction_hierarchy import InstructionHierarchyTool
from cyberredteam.tools.workflow_manipulation import WorkflowManipulationTool


logger = setup_logging()

def _extract_tool_calls(response: str) -> list:
    """Heuristically extract tool-call-like patterns from a free-form LLM response.

    HttpTargetAdapter returns plain text, not structured tool call objects.
    We look for common patterns like "calling employee_lookup" or JSON-like
    fragments that suggest the LLM described a tool invocation.
    """
    import re
    patterns = [
        re.compile(r"(?:call(?:ing)?|invoke[sd]?|using?|ran?)\s+([a-z_]+(?:_tool|_lookup|_search|_executor))", re.IGNORECASE),
        re.compile(r"([a-z_]+)\s*\(\s*(?:['\"]?\w+['\"]?\s*(?:,\s*['\"]?\w+['\"]?)*)\s*\)", re.IGNORECASE),
    ]
    found = []
    for pat in patterns:
        for m in pat.finditer(response):
            found.append(m.group(0))
    return list(set(found))


def _reference_payloads(strategy_type: StrategyType, target_description: str) -> list:
    """Low-quality baseline examples shown to the attacker — its payload must beat these."""
    if strategy_type == StrategyType.PROMPT_INJECTION:
        return PromptInjectionTool.generate_payloads(target_description=target_description)
    if strategy_type == StrategyType.INDIRECT_INJECTION:
        return RAGProbeTool.generate_probes(target_description=target_description)
    if strategy_type == StrategyType.TOOL_MISUSE:
        return ToolAbuseTool.generate_abuse_cases(target_description=target_description)
    if strategy_type == StrategyType.RETRIEVAL_POISONING:
        return RAGProbeTool.generate_probes(target_description=target_description)
    if strategy_type == StrategyType.MEMORY_POISONING:
        return MemoryPoisoningTool.generate_poisoning_payloads(target_description=target_description)
    if strategy_type == StrategyType.SENSITIVE_DATA_EXPOSURE:
        return SensitiveDataExtractor.get_extraction_targets(target_description=target_description)
    if strategy_type == StrategyType.JAILBREAK:
        return JailbreakTool.generate_jailbreak_payloads(target_description=target_description)
    if strategy_type == StrategyType.INSTRUCTION_HIERARCHY:
        return InstructionHierarchyTool.generate_hijack_payloads(target_description=target_description)
    if strategy_type == StrategyType.WORKFLOW_MANIPULATION:
        return WorkflowManipulationTool.generate_dos_payloads(target_description=target_description)
    return []


class AttackerAgent:
    """Generates one LLM-powered adversarial payload per branch and executes it."""

    def __init__(self, target_adapter: Optional[TargetAdapter] = None, llm=None, store=None):
        """Initialize attacker agent.

        Args:
            target_adapter: Optional adapter to execute attacks.
            llm: Optional pre-configured ObservableLLM.
            store: Optional SQLiteStore for call logging.
        """
        self.llm = llm or get_llm_for_agent("attacker", store=store)
        self.system_prompt = load_prompt("attacker")
        # Build LCEL chain once — ChatPromptTemplate | llm.with_structured_output(AttackerOutput)
        self._attack_chain = self.llm.build_structured_chain(self.system_prompt, AttackerOutput)

        if target_adapter is None:
            # Create default based on settings
            from cyberredteam.settings import get_settings
            settings = get_settings()
            if settings.target_mode != "http" or not settings.target_endpoint:
                raise RuntimeError(
                    "An HTTP target is required. Set TARGET_MODE=http and "
                    "TARGET_ENDPOINT to the owned AI agent chat URL."
                )
            self.target_adapter = HttpTargetAdapter(
                endpoint=settings.target_endpoint,
                api_key=settings.target_api_key,
            )
        else:
            self.target_adapter = target_adapter

    def attack_branch(
        self,
        branch: AttackBranch,
        run_id: str,
        target_id: str,
        iteration: int = 0,
    ) -> AttackResult:
        """Generate and execute one attack for a single parallel branch.

        One technique, one payload — the attacker never judges success (that's the
        evaluator's job) and never claims a finding. If the attacker refuses
        (status=ATTACKER_REFUSED), the target is never contacted.
        """
        logger.info(
            f"Attacker branch {branch.branch_id[:8]} — {branch.capability_type} "
            f"({branch.technique_id}) depth={branch.depth} against {target_id}"
        )
        strategy_type = StrategyType(branch.capability_type)
        suggestions = _reference_payloads(strategy_type, target_description=f"Target ID: {target_id}")
        suggestions_str = "\n".join(f"- {s}" for s in suggestions) if suggestions else "None"

        if branch.parent_evidence:
            parent_evidence_str = (
                f"target_response: {branch.parent_evidence.get('target_response', '')}\n"
                f"evaluator_reasoning: {branch.parent_evidence.get('evaluator_reasoning', '')}"
            )
        else:
            parent_evidence_str = "None (depth 0 — first attempt on this branch)"

        user_message = (
            f"capability_type: {branch.capability_type}\n"
            f"technique_id: {branch.technique_id}\n"
            f"technique_spec: {branch.technique_spec}\n"
            f"target_metadata: {json.dumps(branch.target_metadata)}\n"
            f"depth: {branch.depth}\n"
            f"attempt_budget_remaining: {branch.attempt_budget_remaining}\n"
            f"parent_evidence:\n{parent_evidence_str}\n\n"
            f"reference_examples (low-quality baseline — your payload must be more sophisticated):\n"
            f"{suggestions_str}\n"
        )

        try:
            output: AttackerOutput = self.llm.invoke_chain(
                self._attack_chain, user_message, system_context=self.system_prompt
            )
            # Force the echo fields — the attacker must not drift from its assignment.
            output.capability_type = branch.capability_type
            output.technique_id = branch.technique_id
            output.depth = branch.depth
        except Exception as e:
            logger.error(f"Failed to generate attacker output: {e}")
            # Fail closed: never send a prewritten payload when the attacker model
            # is unavailable. The target is not contacted for this branch.
            return AttackResult(
                run_id=run_id,
                target_id=target_id,
                attempt_number=branch.depth + 1,
                strategy_type=strategy_type,
                prompt="",
                response="",
                success=False,
                severity=AttackSeverity.INFO,
                score=0.0,
                error=f"attacker model unavailable: {e}",
                indicators={
                    "_llm_error": True,
                    "error": str(e),
                    "technique_id": branch.technique_id,
                    "capability_type": branch.capability_type,
                },
                timestamp=datetime.utcnow(),
                technique_id=branch.technique_id,
                capability_type=branch.capability_type,
                depth=branch.depth,
                branch_id=branch.branch_id,
                iteration=iteration,
            )

        if output.status == "ATTACKER_REFUSED":
            logger.warning(f"Attacker refused branch {branch.branch_id[:8]}: {output.refusal_reason}")
            return AttackResult(
                run_id=run_id,
                target_id=target_id,
                attempt_number=branch.depth + 1,
                strategy_type=strategy_type,
                prompt="",
                response="",
                success=False,
                severity=AttackSeverity.INFO,
                score=0.0,
                error=output.refusal_reason or "attacker refused",
                indicators={"_refused": True, "refusal_reason": output.refusal_reason},
                timestamp=datetime.utcnow(),
                technique_id=branch.technique_id,
                capability_type=branch.capability_type,
                depth=branch.depth,
                mutation_of_parent=output.mutation_of_parent,
                branch_id=branch.branch_id,
                iteration=iteration,
            )

        if hasattr(self.target_adapter, "target_id"):
            self.target_adapter.target_id = target_id

        adversarial_input = output.payload
        result_tuple = self.target_adapter.execute_attack(output.payload, label=branch.technique_id)
        if isinstance(result_tuple, tuple):
            response, canary = result_tuple
        else:
            # Backwards-compatible: bare string (e.g. mocked adapters in tests)
            response, canary = result_tuple, None

        spec = get_spec(branch.technique_id)
        indicators: dict = {
            "objective": output.rationale,
            "expected_failure": spec["expected_failure"],
            # Stored for Phase 4 replay: what the target MUST do to pass retest.
            "expected_safe_behavior": spec["expected_safe_behavior"],
            # Raw trace data — orchestrator's _persist_artifacts writes TraceRecord
            "_trace": {
                "adversarial_input": adversarial_input,
                "target_response": response,
                "tool_calls_observed": _extract_tool_calls(response),
            },
            "technique_id": branch.technique_id,
            "capability_type": branch.capability_type,
            "depth": branch.depth,
            "mutation_of_parent": output.mutation_of_parent,
        }
        if canary:
            indicators["_canary"] = canary

        return AttackResult(
            run_id=run_id,
            target_id=target_id,
            attempt_number=branch.depth + 1,
            strategy_type=strategy_type,
            prompt=output.payload,
            response=response,
            success=False,  # Evaluator determines success
            severity=AttackSeverity.MEDIUM,
            score=0.0,      # Evaluator determines score
            indicators=indicators,
            timestamp=datetime.utcnow(),
            technique_id=branch.technique_id,
            capability_type=branch.capability_type,
            depth=branch.depth,
            mutation_of_parent=output.mutation_of_parent,
            branch_id=branch.branch_id,
            iteration=iteration,
        )
