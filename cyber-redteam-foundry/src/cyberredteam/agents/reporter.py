"""Reporter agent - generates final reports using LLM narratives and deterministic metrics."""

import json
from datetime import datetime
from pathlib import Path
from typing import List

from cyberredteam.llm.factory import get_llm_for_agent, load_prompt
from cyberredteam.llm.schemas import SecurityReport
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackResult, PatchResult, RedTeamReport

logger = setup_logging()


class ReporterAgent:
    """Generates red team reports in multiple formats using LLM-generated explanations."""

    def __init__(self, output_dir: Path, llm=None, store=None):
        """Initialize reporter agent.

        Args:
            output_dir: Directory for report output.
            llm: Optional pre-configured ObservableLLM.
            store: Optional SQLiteStore for call logging.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.llm = llm or get_llm_for_agent("reporter", store=store)
        self.system_prompt = load_prompt("reporter")

    def generate_report(
        self,
        run_id: str,
        target_id: str,
        attack_results: List[AttackResult],
        patches: List[PatchResult],
        start_time: datetime,
        end_time: datetime,
    ) -> RedTeamReport:
        """Generate comprehensive red team report using LLM for narratives.

        Args:
            run_id: Run identifier.
            target_id: Target identifier.
            attack_results: List of attack results.
            patches: List of patches applied.
            start_time: Run start time.
            end_time: Run end time.

        Returns:
            RedTeamReport object.
        """
        logger.info(f"Reporter generating report for run {run_id}")

        # 1. Compute statistics deterministically (never from LLM alone)
        total_attacks = len(attack_results)
        successful_attacks = sum(1 for r in attack_results if r.success)
        success_rate = successful_attacks / total_attacks if total_attacks > 0 else 0.0

        # Severity distribution
        severity_dist = {}
        for result in attack_results:
            key = result.severity
            severity_dist[key] = severity_dist.get(key, 0) + 1

        # Format input facts for LLM narrative generation
        attacks_fact = []
        for r in attack_results:
            attacks_fact.append(
                f"- Attempt {r.attempt_number}: Strategy={r.strategy_type.value}, "
                f"Success={r.success}, Severity={r.severity.value}, "
                f"Objective={r.indicators.get('objective', 'N/A')}"
            )
        attacks_fact_str = "\n".join(attacks_fact) if attacks_fact else "None"

        patches_fact = []
        for p in patches:
            patches_fact.append(
                f"- Patch {p.patch_id}: Type={p.patch_type.value}, Applied={p.applied}, "
                f"RetestPassed={p.retest_passed}, Component={p.target_component}"
            )
        patches_fact_str = "\n".join(patches_fact) if patches_fact else "None"

        user_message = (
            f"Run ID: {run_id}\n"
            f"Target ID: {target_id}\n"
            f"Factual Attack Log:\n{attacks_fact_str}\n\n"
            f"Factual Patches Log:\n{patches_fact_str}\n"
        )

        try:
            # 2. Invoke LLM to generate narrative explanations
            sec_report: SecurityReport = self.llm.invoke_structured(
                system_prompt=self.system_prompt,
                user_message=user_message,
                output_schema=SecurityReport,
            )

            narratives = {
                "executive_summary": sec_report.executive_summary,
                "attack_campaign": sec_report.attack_campaign,
                "vulnerabilities_found": sec_report.vulnerabilities_found,
                "evidence_summary": sec_report.evidence_summary,
                "fixes_applied": sec_report.fixes_applied,
                "regression_results": sec_report.regression_results,
                "remaining_risks": sec_report.remaining_risks,
                "assumptions": sec_report.assumptions,
            }
        except Exception as e:
            logger.error(f"Reporter agent failed to generate narratives: {e}")
            # Fallback narratives
            narratives = {
                "executive_summary": "Security assessment complete. Factual metrics are listed below.",
                "attack_campaign": "Assessment of targeted strategies against the system.",
                "vulnerabilities_found": "Vulnerabilities discovered and logged during testing.",
                "evidence_summary": "Evidence gathered from agent outputs.",
                "fixes_applied": "Remediation patches applied by the defender.",
                "regression_results": "Retesting performed on applied patches.",
                "remaining_risks": "Residual risks based on remaining unmitigated findings.",
                "assumptions": "Assessment assumptions and scope boundaries.",
            }

        # Recommendations
        recommendations = self._generate_recommendations(attack_results, patches)

        # Assumptions list
        assumptions_list = [
            "Target is sandbox or owned deployment.",
            "LLM narratives are generated based on deterministic logs.",
            "Checkpoints and persistence are active."
        ]

        report = RedTeamReport(
            run_id=run_id,
            target_id=target_id,
            start_time=start_time,
            end_time=end_time,
            total_attacks=total_attacks,
            successful_attacks=successful_attacks,
            attack_results=attack_results,
            patches_applied=patches,
            severity_distribution=severity_dist,
            success_rate=success_rate,
            recommendations=recommendations,
            assumptions=assumptions_list,
            narratives=narratives,
        )

        logger.info(f"Generated report: {total_attacks} attacks, {success_rate:.1%} success")
        return report

    def write_markdown(self, report: RedTeamReport) -> Path:
        """Write report in Markdown format with required sections."""
        output_file = self.output_dir / f"{report.run_id}_report.md"

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"# Red Team Report: {report.run_id}\n\n")
            f.write(f"**Target:** {report.target_id}\n")
            f.write(f"**Date:** {report.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## Executive Summary\n\n")
            f.write(f"{report.narratives.get('executive_summary', '')}\n\n")
            f.write("### Factual Metrics\n")
            f.write(f"- **Total Attacks:** {report.total_attacks}\n")
            f.write(f"- **Successful Attacks:** {report.successful_attacks}\n")
            f.write(f"- **Success Rate:** {report.success_rate:.1%}\n")
            f.write(f"- **Patches Applied:** {len(report.patches_applied)}\n\n")

            f.write("## Attack Campaign\n\n")
            f.write(f"{report.narratives.get('attack_campaign', '')}\n\n")

            f.write("## Vulnerabilities Found\n\n")
            f.write(f"{report.narratives.get('vulnerabilities_found', '')}\n\n")

            f.write("## Evidence\n\n")
            f.write(f"{report.narratives.get('evidence_summary', '')}\n\n")

            f.write("## Fixes Applied\n\n")
            f.write(f"{report.narratives.get('fixes_applied', '')}\n\n")

            f.write("## Regression Results\n\n")
            f.write(f"{report.narratives.get('regression_results', '')}\n\n")

            f.write("## Remaining Risks\n\n")
            f.write(f"{report.narratives.get('remaining_risks', '')}\n\n")

            f.write("## Assumptions\n\n")
            f.write(f"{report.narratives.get('assumptions', '')}\n\n")

            # Recommendations
            f.write("## Recommendations\n\n")
            for i, rec in enumerate(report.recommendations, 1):
                f.write(f"{i}. {rec}\n")

        logger.info(f"Wrote Markdown report to {output_file}")
        return output_file

    def write_json(self, report: RedTeamReport) -> Path:
        """Write report in JSON format."""
        output_file = self.output_dir / f"{report.run_id}_report.json"

        data = {
            "run_id": report.run_id,
            "target_id": report.target_id,
            "start_time": report.start_time.isoformat(),
            "end_time": report.end_time.isoformat(),
            "total_attacks": report.total_attacks,
            "successful_attacks": report.successful_attacks,
            "success_rate": report.success_rate,
            "attacks": [
                {
                    "attempt": r.attempt_number,
                    "strategy": r.strategy_type.value,
                    "success": r.success,
                    "severity": r.severity.value,
                    "score": r.score,
                }
                for r in report.attack_results
            ],
            "patches": [
                {
                    "patch_id": p.patch_id,
                    "type": p.patch_type.value,
                    "applied": p.applied,
                    "retest_passed": p.retest_passed,
                }
                for p in report.patches_applied
            ],
            "recommendations": report.recommendations,
            "assumptions": report.assumptions,
            "narratives": report.narratives,
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Wrote JSON report to {output_file}")
        return output_file

    def _generate_recommendations(
        self,
        attack_results: List[AttackResult],
        patches: List[PatchResult],
    ) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        successful = [r for r in attack_results if r.success]
        if not successful:
            recommendations.append("No successful attacks detected. Target appears secure.")
            return recommendations

        # Check for injection vulnerabilities
        injection_attacks = [r for r in successful if "injection" in r.strategy_type.value]
        if injection_attacks:
            recommendations.append(
                "Implement prompt hardening to resist injection attacks"
            )

        # Check for tool misuse
        tool_attacks = [r for r in successful if "tool" in r.strategy_type.value]
        if tool_attacks:
            recommendations.append("Implement strict tool access policies")

        # Check for retrieval issues
        retrieval_attacks = [
            r for r in successful if "retrieval" in r.strategy_type.value
        ]
        if retrieval_attacks:
            recommendations.append("Add content filtering for retrieved documents")

        # Check patch effectiveness
        retest_failures = [p for p in patches if p.applied and not p.retest_passed]
        if retest_failures:
            recommendations.append(
                f"Investigate {len(retest_failures)} patches that failed retest"
            )

        if not recommendations:
            recommendations.append("Continue monitoring for new attack vectors")

        return recommendations
