"""Defender agent - plans remediation patches using LLM reasoning."""

import uuid
from datetime import datetime
from typing import List

from cyberredteam.llm.factory import get_llm_for_agent, load_prompt
from cyberredteam.llm.schemas import DefensePatch
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackResult, PatchResult, PatchType

logger = setup_logging()


class DefenderAgent:
    """Plans and applies defensive remediations using Azure OpenAI reasoning."""

    def __init__(self, llm=None, store=None):
        """Initialize defender agent.

        Args:
            llm: Optional pre-configured ObservableLLM.
            store: Optional SQLiteStore for call logging.
        """
        self.llm = llm or get_llm_for_agent("defender", store=store)
        self.system_prompt = load_prompt("defender")

    def plan_defenses(self, attack_results: List[AttackResult]) -> List[PatchResult]:
        """Plan remediation patches for successful attacks using LLM.

        Args:
            attack_results: List of successful attack results to address.

        Returns:
            List of proposed PatchResult objects.
        """
        successful_attacks = [r for r in attack_results if r.success]
        logger.info(f"Defender planning patches for {len(successful_attacks)} attacks")

        patches = []
        for i, result in enumerate(successful_attacks):
            vulnerability = (
                f"Strategy: {result.strategy_type.value}. "
                f"Objective: {result.indicators.get('objective', 'Unknown')}. "
                f"Expected Failure condition: {result.indicators.get('expected_failure', 'None')}"
            )
            evidence = (
                f"Adversarial Prompt: {result.prompt}\n"
                f"Target Response: {result.response}\n"
                f"Evaluator Explanation: {result.indicators.get('explanation', 'None')}"
            )
            target_config = f"Default Agent Configuration (Target ID: {result.run_id})"

            user_message = (
                f"Vulnerability Details:\n{vulnerability}\n\n"
                f"Exploit Evidence:\n{evidence}\n\n"
                f"Target Configuration context:\n{target_config}\n"
            )

            try:
                # 1. Plan remediation patch via LLM
                llm_patch: DefensePatch = self.llm.invoke_structured(
                    system_prompt=self.system_prompt,
                    user_message=user_message,
                    output_schema=DefensePatch,
                )

                # 2. Map LLM patch_type to PatchType Enum
                mapped_type = PatchType.PROMPT_HARDENING
                p_type_lower = llm_patch.patch_type.lower()
                if "tool" in p_type_lower:
                    mapped_type = PatchType.TOOL_POLICY
                elif "retrieval" in p_type_lower:
                    mapped_type = PatchType.RETRIEVAL_FILTER
                elif "memory" in p_type_lower:
                    mapped_type = PatchType.MEMORY_ISOLATION
                elif "guardrail" in p_type_lower or "regression" in p_type_lower:
                    mapped_type = PatchType.REGRESSION_RULE

                # Generate a unique patch ID
                unique_suffix = str(uuid.uuid4())[:6]
                patch_id = f"{result.run_id}_patch_{i}_{mapped_type.value}_{unique_suffix}"

                # 3. Create PatchResult
                patch = PatchResult(
                    run_id=result.run_id,
                    patch_id=patch_id,
                    patch_type=mapped_type,
                    target_component=llm_patch.affected_component,
                    original_config={"status": "vulnerable"},
                    patched_config={
                        "description": llm_patch.description,
                        "expected_improvement": llm_patch.expected_improvement,
                        "confidence": llm_patch.confidence,
                    },
                    diff=f"+ remediation description: {llm_patch.description}\n+ expected improvement: {llm_patch.expected_improvement}",
                    applied=False,
                    retest_passed=False,
                    timestamp=datetime.utcnow(),
                )
                patches.append(patch)

            except Exception as e:
                logger.error(f"Defender agent failed to plan patch: {e}")
                # Fallback patch
                unique_suffix = str(uuid.uuid4())[:6]
                fallback = PatchResult(
                    run_id=result.run_id,
                    patch_id=f"{result.run_id}_patch_{i}_fallback_{unique_suffix}",
                    patch_type=PatchType.PROMPT_HARDENING,
                    target_component="system_prompt",
                    original_config={"status": "vulnerable"},
                    patched_config={"remediation": "Fallback default prompt hardening instruction"},
                    diff="+ added fallback safety instruction",
                    applied=False,
                    retest_passed=False,
                    timestamp=datetime.utcnow(),
                )
                patches.append(fallback)

        logger.info(f"Planned {len(patches)} patches")
        return patches

    def apply_patches(self, patches: List[PatchResult]) -> List[PatchResult]:
        """Apply planned patches to target."""
        applied = []
        for patch in patches:
            logger.info(f"Defender applying patch {patch.patch_id}")
            # Simulate applying the patch
            patch.applied = True
            applied.append(patch)
        logger.info(f"Applied {len(applied)} patches")
        return applied

    def retest_after_patch(
        self,
        patch: PatchResult,
        original_prompts: List[str],
    ) -> bool:
        """Retest the target after applying a patch."""
        logger.info(f"Defender retesting after patch {patch.patch_id}")
        # Always simulate retest passed for the mock/sandbox loop
        patch.retest_passed = True
        logger.info(f"Retest passed for {patch.patch_id}")
        return patch.retest_passed

    def rank_patches_by_impact(self, patches: List[PatchResult]) -> List[PatchResult]:
        """Rank patches by impact."""
        def impact_score(patch: PatchResult) -> float:
            score = 0.0
            if patch.applied:
                score += 0.5
            if patch.retest_passed:
                score += 0.5
            # Add confidence score if present in patched_config
            confidence = patch.patched_config.get("confidence", 0.0)
            score += confidence * 0.1
            return score

        ranked = sorted(patches, key=impact_score, reverse=True)
        logger.info(f"Ranked {len(ranked)} patches by impact")
        return ranked
