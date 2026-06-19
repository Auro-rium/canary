"""Attacker agent - generates attack cases and executes them against targets."""

from datetime import datetime
from typing import List, Optional

from cyberredteam.llm.factory import get_llm_for_agent, load_prompt
from cyberredteam.llm.schemas import AttackCase
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackResult, AttackSeverity, PatchResult, StrategyType
from cyberredteam.tools.target_adapter import (
    FoundryAgentTargetAdapter,
    HttpTargetAdapter,
    SandboxTargetAdapter,
    TargetAdapter,
)
from cyberredteam.tools.prompt_injection import PromptInjectionTool
from cyberredteam.tools.sensitive_data import SensitiveDataExtractor
from cyberredteam.tools.tool_abuse import ToolAbuseTool
from cyberredteam.tools.memory_poisoning import MemoryPoisoningTool
from cyberredteam.tools.rag_probe import RAGProbeTool


logger = setup_logging()


class AttackerAgent:
    """Generates LLM-powered adversarial attack cases and executes them."""

    def __init__(self, target_adapter: Optional[TargetAdapter] = None, llm=None, use_foundry: bool = False, store=None):
        """Initialize attacker agent.

        Args:
            target_adapter: Optional adapter to execute attacks.
            llm: Optional pre-configured ObservableLLM.
            use_foundry: Deprecated, kept for factory backward compatibility.
            store: Optional SQLiteStore for call logging.
        """
        self.llm = llm or get_llm_for_agent("attacker", store=store)
        self.system_prompt = load_prompt("attacker")

        if target_adapter is None:
            # Create default based on settings
            from cyberredteam.settings import get_settings
            settings = get_settings()
            if settings.target_mode == "http" and settings.target_endpoint:
                self.target_adapter = HttpTargetAdapter(
                    endpoint=settings.target_endpoint,
                    api_key=settings.target_api_key,
                )
            elif settings.target_mode == "foundry_agent":
                self.target_adapter = FoundryAgentTargetAdapter(
                    agent_id=settings.target_endpoint or "default-agent"
                )
            else:
                self.target_adapter = SandboxTargetAdapter(target_id="sandbox-target-001")
        else:
            self.target_adapter = target_adapter

    def generate_attack_case(
        self,
        strategy_type: StrategyType,
        target_description: str,
        previous_attempts: List[AttackResult],
        known_defenses: List[PatchResult],
    ) -> AttackCase:
        """Generate a single attack case using LLM.

        Args:
            strategy_type: The strategy type being executed.
            target_description: Description of the target system.
            previous_attempts: Previous attempts and results.
            known_defenses: Previously applied patches.

        Returns:
            An AttackCase Pydantic model.
        """
        # Format history
        attempts_list = []
        for r in previous_attempts:
            attempts_list.append(
                f"- Attempt {r.attempt_number} ({r.strategy_type.value}):\n"
                f"  Prompt: {r.prompt}\n"
                f"  Response: {r.response}\n"
                f"  Success: {r.success}"
            )
        attempts_str = "\n".join(attempts_list) if attempts_list else "None"

        defenses_list = []
        for p in known_defenses:
            defenses_list.append(
                f"- Patch ID: {p.patch_id} ({p.patch_type.value}):\n"
                f"  Description: {p.target_component}\n"
                f"  Diff: {p.diff}"
            )
        defenses_str = "\n".join(defenses_list) if defenses_list else "None"

        # Select reference payloads to assist generation
        suggestions = []
        if strategy_type == StrategyType.PROMPT_INJECTION:
            suggestions = PromptInjectionTool.generate_payloads()
        elif strategy_type == StrategyType.INDIRECT_INJECTION:
            suggestions = RAGProbeTool.generate_probes()
        elif strategy_type == StrategyType.TOOL_MISUSE:
            suggestions = ToolAbuseTool.generate_abuse_cases()
        elif strategy_type == StrategyType.RETRIEVAL_POISONING:
            suggestions = RAGProbeTool.generate_probes()
        elif strategy_type == StrategyType.JAILBREAK:
            suggestions = MemoryPoisoningTool.generate_poisoning_payloads()
        elif strategy_type == StrategyType.LEAKAGE:
            suggestions = SensitiveDataExtractor.get_extraction_targets()

        suggestions_str = "\n".join([f"- {s}" for s in suggestions]) if suggestions else "None"

        user_message = (
            f"Strategy: {strategy_type.value}\n"
            f"Target Description: {target_description}\n"
            f"Reference Payload Examples:\n{suggestions_str}\n\n"
            f"Previous Attempts:\n{attempts_str}\n\n"
            f"Known Defenses:\n{defenses_str}\n"
        )


        try:
            attack_case: AttackCase = self.llm.invoke_structured(
                system_prompt=self.system_prompt,
                user_message=user_message,
                output_schema=AttackCase,
            )
            # Ensure the output strategy matches what we asked
            attack_case.attack_type = strategy_type.value
            return attack_case
        except Exception as e:
            logger.error(f"Failed to generate attack case: {e}")
            # Fallback
            return AttackCase(
                attack_type=strategy_type.value,
                objective="Fallback default attack",
                generated_test_case=f"Default attack test case for {strategy_type.value}",
                expected_failure="Default expected behavior",
                severity_guess="medium",
            )

    def attack(
        self,
        run_id: str,
        target_id: str,
        strategy_type: StrategyType,
        attempt_number: int,
        previous_attempts: Optional[List[AttackResult]] = None,
        known_defenses: Optional[List[PatchResult]] = None,
    ) -> AttackResult:
        """Generate and execute a single attack.

        Args:
            run_id: The run identifier.
            target_id: The target identifier.
            strategy_type: The strategy type.
            attempt_number: Current attempt sequence number.
            previous_attempts: Historical attempts.
            known_defenses: Applied patches.

        Returns:
            AttackResult wrapping execution outputs.
        """
        logger.info(
            f"Attacker executing {strategy_type.value} "
            f"against {target_id} (attempt {attempt_number})"
        )

        prev = previous_attempts or []
        defenses = known_defenses or []

        # 1. Generate attack case
        attack_case = self.generate_attack_case(
            strategy_type=strategy_type,
            target_description=f"Target ID: {target_id}",
            previous_attempts=prev,
            known_defenses=defenses,
        )

        # 2. Execute attack via target adapter
        if hasattr(self.target_adapter, "target_id"):
            self.target_adapter.target_id = target_id
        response = self.target_adapter.execute_attack(attack_case)

        # 3. Initially parse severity guess (refined by evaluator later)
        try:
            severity = AttackSeverity(attack_case.severity_guess.lower())
        except ValueError:
            severity = AttackSeverity.MEDIUM

        return AttackResult(
            run_id=run_id,
            attempt_number=attempt_number,
            strategy_type=strategy_type,
            prompt=attack_case.generated_test_case,
            response=response,
            success=False,  # Evaluator determines success
            severity=severity,
            score=0.0,      # Evaluator determines score
            indicators={
                "objective": attack_case.objective,
                "expected_failure": attack_case.expected_failure,
            },
            timestamp=datetime.utcnow(),
        )

    def batch_attack(
        self,
        run_id: str,
        target_id: str,
        strategies: List[StrategyType],
        max_attempts_per_strategy: int = 3,
        previous_attempts: Optional[List[AttackResult]] = None,
        known_defenses: Optional[List[PatchResult]] = None,
    ) -> List[AttackResult]:
        """Execute multiple attacks across strategies."""
        results = []

        # Start numbering from the next index based on previous attempts
        prev = previous_attempts or []
        attempt_number = len(prev) + 1

        for strategy in strategies:
            for _ in range(max_attempts_per_strategy):
                # Pass accumulated results so far during this batch to subsequent attempts
                all_prev = prev + results
                result = self.attack(
                    run_id=run_id,
                    target_id=target_id,
                    strategy_type=strategy,
                    attempt_number=attempt_number,
                    previous_attempts=all_prev,
                    known_defenses=known_defenses,
                )
                if result:
                    results.append(result)
                attempt_number += 1

        logger.info(f"Completed batch attack: {len(results)} total results")
        return results
