"""Strategist agent - selects attack strategies using LLM reasoning."""

from typing import List, Optional

from cyberredteam.attack_strategies.registry import list_strategies
from cyberredteam.llm.factory import get_llm_for_agent, load_prompt
from cyberredteam.llm.schemas import AttackPlan
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import StrategyType

logger = setup_logging()


class StrategistAgent:
    """Selects attack strategies using Backboard reasoning via a typed chain."""

    def __init__(self, llm=None, store=None):
        """Initialize strategist agent.

        Args:
            llm: Optional pre-configured ObservableLLM.
            store: Optional SQLiteStore for call logging.
        """
        self.llm = llm or get_llm_for_agent("strategist", store=store)
        self.available_strategies = list_strategies()
        self.system_prompt = load_prompt("strategist")
        # Build LCEL chain once — ChatPromptTemplate | llm.with_structured_output(AttackPlan)
        self._select_chain = self.llm.build_structured_chain(self.system_prompt, AttackPlan)

    def select_strategies(
        self,
        target_id: str,
        risk_appetite: str = "medium",
        count: int = 3,
        previous_vulnerabilities: Optional[List[str]] = None,
        available_subset: Optional[List[str]] = None,
    ) -> List[StrategyType]:
        """Select attack strategies using LLM reasoning.

        Args:
            target_id: ID of the target to attack.
            risk_appetite: Risk tolerance level (low, medium, high).
            count: Number of strategies to select.
            previous_vulnerabilities: List of previously identified vulnerabilities.
            available_subset: Subset of strategy names to choose from.

        Returns:
            List of selected StrategyType enums.
        """
        logger.info(
            f"Strategist selecting {count} strategies "
            f"for target {target_id} (risk={risk_appetite})"
        )

        candidates = available_subset or [s.value for s in self.available_strategies]
        vulnerabilities_str = ", ".join(previous_vulnerabilities) if previous_vulnerabilities else "None"

        user_message = (
            f"Target ID: {target_id}\n"
            f"Risk Appetite: {risk_appetite}\n"
            f"Requested Selection Count: {count}\n"
            f"Candidate Strategies to choose from: {', '.join(candidates)}\n"
            f"Previously Detected Vulnerabilities: {vulnerabilities_str}\n"
        )

        try:
            plan: AttackPlan = self.llm.invoke_chain(
                self._select_chain, user_message, system_context=self.system_prompt
            )

            # Filter selected strategies: must exist in registry & in candidates
            selected_types = []
            for s in plan.categories:
                try:
                    strategy_enum = StrategyType(s.strip())
                    if strategy_enum.value in candidates:
                        selected_types.append(strategy_enum)
                except ValueError:
                    logger.warning(f"Strategist recommended invalid strategy: {s}")

            # An invalid/empty LLM plan is an execution failure. Never replace
            # an absent model decision with canned deterministic attacks.
            if not selected_types:
                raise RuntimeError("Strategist returned no valid configured strategies")

            # Ensure we return at most `count` strategies
            selected_types = selected_types[:count]

            logger.info(f"Strategist selected: {[s.value for s in selected_types]}")
            return selected_types

        except Exception as e:
            logger.error(f"Strategist agent failed to select strategies: {e}")
            raise RuntimeError("Strategist LLM execution failed; refusing deterministic fallback") from e

    def evaluate_coverage(self, executed_strategies: List[StrategyType]) -> dict:
        """Evaluate attack coverage across strategy families."""
        coverage = {
            "injection": 0,
            "tool_abuse": 0,
            "data_extraction": 0,
            "logic_manipulation": 0,
            "safety_bypass": 0,
        }

        for strategy in executed_strategies:
            if "injection" in strategy.value:
                coverage["injection"] += 1
            elif "tool" in strategy.value:
                coverage["tool_abuse"] += 1
            elif "sensitive_data" in strategy.value or "retrieval" in strategy.value:
                coverage["data_extraction"] += 1
            elif "jailbreak" in strategy.value:
                coverage["safety_bypass"] += 1

        total = len(executed_strategies)
        for key in list(coverage.keys()):
            coverage[f"{key}_pct"] = (
                coverage[key] / total if total > 0 else 0
            ) * 100

        logger.info(f"Coverage analysis: {coverage}")
        return coverage

    def rank_by_risk(self) -> List[tuple]:
        """Rank all strategies by risk level."""
        from cyberredteam.attack_strategies.registry import get_risk_level
        rankings = []
        for strategy in self.available_strategies:
            risk = get_risk_level(strategy)
            rankings.append((strategy, risk))

        rankings.sort(key=lambda x: {"low": 0, "medium": 1, "high": 2}.get(x[1], 1))
        return rankings
