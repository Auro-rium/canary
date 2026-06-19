"""Defense patch planning."""

from typing import List

from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackResult, PatchResult, PatchType

logger = setup_logging()


class PatchPlanner:
    """Convert attack failures into concrete patches."""

    @staticmethod
    def plan_patches(attack_results: List[AttackResult]) -> List[PatchResult]:
        """
        Generate patches based on attack results.

        Args:
            attack_results: List of failed attacks to address

        Returns:
            List of proposed patches
        """
        patches = []

        for i, result in enumerate(attack_results):
            if result.success:
                # Direct prompt injection -> prompt hardening
                if "injection" in result.strategy_type.value:
                    patch = PatchResult(
                        run_id=result.run_id,
                        patch_id=f"{result.run_id}_patch_{i}_hardening",
                        patch_type=PatchType.PROMPT_HARDENING,
                        target_component="system_prompt",
                        original_config={
                            "instruction": "Be helpful",
                        },
                        patched_config={
                            "instruction": "Be helpful but refuse harmful requests",
                            "safety_check": True,
                        },
                        diff="+ safety_check: true",
                        applied=False,
                        retest_passed=False,
                    )
                    patches.append(patch)

                # Tool misuse -> tool policy
                if "tool" in result.strategy_type.value:
                    patch = PatchResult(
                        run_id=result.run_id,
                        patch_id=f"{result.run_id}_patch_{i}_tool_policy",
                        patch_type=PatchType.TOOL_POLICY,
                        target_component="tool_definitions",
                        original_config={
                            "tools": ["execute", "file_read", "search"],
                        },
                        patched_config={
                            "tools": ["execute", "file_read", "search"],
                            "restrictions": {
                                "execute": "whitelist_only",
                                "file_read": "safe_paths_only",
                            },
                        },
                        diff="+ restrictions policy for sensitive tools",
                        applied=False,
                        retest_passed=False,
                    )
                    patches.append(patch)

                # Retrieval poisoning -> retrieval filter
                if "retrieval" in result.strategy_type.value:
                    patch = PatchResult(
                        run_id=result.run_id,
                        patch_id=f"{result.run_id}_patch_{i}_retrieval",
                        patch_type=PatchType.RETRIEVAL_FILTER,
                        target_component="rag_filter",
                        original_config={
                            "filter_enabled": False,
                        },
                        patched_config={
                            "filter_enabled": True,
                            "filter_rules": ["content_hash_check", "source_verify"],
                        },
                        diff="+ content filtering for retrieved documents",
                        applied=False,
                        retest_passed=False,
                    )
                    patches.append(patch)

        logger.info(f"Planned {len(patches)} patches for {len(attack_results)} attacks")
        return patches

    @staticmethod
    def apply_patch(patch: PatchResult) -> bool:
        """Apply a patch to the target."""
        try:
            # Placeholder: Real implementation updates target config
            logger.info(
                f"Applied patch {patch.patch_id} to {patch.target_component}"
            )
            patch.applied = True
            return True
        except Exception as e:
            logger.error(f"Failed to apply patch {patch.patch_id}: {e}")
            return False
