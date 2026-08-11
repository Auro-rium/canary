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


logger = setup_logging()

def _extract_tool_calls(response: str) -> list:
    """Heuristically extract tool-call-like patterns from a free-form LLM response.

    HTTP targets return plain text, not structured tool call objects.
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
            from cyberredteam.settings import get_settings
            settings = get_settings()
            if not settings.target_endpoint:
                raise ValueError(
                    "An HTTP target endpoint is required; pass target_adapter or set TARGET_ENDPOINT"
                )
            self.target_adapter = HttpTargetAdapter(
                endpoint=settings.target_endpoint,
                api_key=settings.target_api_key,
                allow_private_targets=settings.allow_private_targets,
            )
        else:
            self.target_adapter = target_adapter

    def _llm_failure_output(self, branch: AttackBranch, error: Exception) -> AttackerOutput:
        """Represent an unavailable attacker model without fabricating a payload."""
        return AttackerOutput(
            status="ATTACKER_REFUSED",
            capability_type=branch.capability_type,
            technique_id=branch.technique_id,
            depth=branch.depth,
            payload="",
            rationale="The attacker model was unavailable; no synthetic payload was generated.",
            refusal_reason=f"attacker model unavailable: {error.__class__.__name__}",
            mutation_of_parent=None,
        )

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
            "Generate the complete adversarial payload yourself. Do not copy a canned example "
            "or rely on a deterministic payload library.\n"
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
            output = self._llm_failure_output(branch, e)

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
                "http_status_code": getattr(self.target_adapter, "last_status_code", None),
                "http_latency_ms": getattr(self.target_adapter, "last_latency_ms", None),
                "request_hash": getattr(self.target_adapter, "last_request_hash", None),
                "response_hash": getattr(self.target_adapter, "last_response_hash", None),
            },
            "technique_id": branch.technique_id,
            "capability_type": branch.capability_type,
            "depth": branch.depth,
            "mutation_of_parent": output.mutation_of_parent,
        }
        if canary:
            indicators["_canary"] = canary

        adapter_error = getattr(self.target_adapter, "last_error", None)
        if adapter_error:
            indicators["target_request_failed"] = True

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
            error=adapter_error,
        )
