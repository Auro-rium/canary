"""Reporter agent - generates final reports using LLM narratives and deterministic metrics."""

import json
from datetime import datetime
from pathlib import Path
from typing import List

from cyberredteam.llm.factory import get_llm_for_agent, load_prompt
from cyberredteam.llm.schemas import SecurityReport
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackResult, RedTeamReport

logger = setup_logging()

# Hardcoded per the reporter spec — must not be LLM-generated.
_ASSUMPTIONS = [
    "Target is sandbox or owned deployment.",
    "Attack traces stored at run_id level in object store.",
    "Evaluator verdicts are evidence-based. Inconclusive verdicts are not resolved automatically.",
]


class ReporterAgent:
    """Generates red team reports in multiple formats using LLM-generated narratives."""

    def __init__(self, output_dir: Path, llm=None, store=None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.llm = llm or get_llm_for_agent("reporter", store=store)
        self.system_prompt = load_prompt("reporter")
        # Build LCEL chain once — ChatPromptTemplate | llm.with_structured_output(SecurityReport)
        self._report_chain = self.llm.build_structured_chain(self.system_prompt, SecurityReport)

    def generate_report(
        self,
        run_id: str,
        target_id: str,
        attack_results: List[AttackResult],
        start_time: datetime,
        end_time: datetime,
    ) -> RedTeamReport:
        """Generate comprehensive red team report using LLM for narratives."""
        logger.info(f"Reporter generating report for run {run_id}")

        total_attacks = len(attack_results)
        successful_attacks = sum(1 for r in attack_results if r.success)
        success_rate = successful_attacks / total_attacks if total_attacks > 0 else 0.0

        severity_dist = {}
        for result in attack_results:
            key = result.severity
            severity_dist[key] = severity_dist.get(key, 0) + 1

        # Build richer attack context for LLM — include finding_ids, det_hits, components
        attacks_fact = []
        for r in attack_results:
            verdict = r.indicators.get("verdict", "unknown")
            finding_id = r.finding_id or "—"
            det_hits = r.indicators.get(
                "deterministic_hits",
                list(r.indicators.get("deterministic_checks", {}).keys()),
            )
            asi_class = r.indicators.get("asi_class", "")
            component = r.indicators.get("component", "")
            atlas = r.indicators.get("atlas_technique", "")
            inconclusive_reason = (
                r.indicators.get("_verdict", {}).get("inconclusive_reason", "") or ""
            )
            attacks_fact.append(
                f"- Attempt {r.attempt_number}: strategy={r.strategy_type.value}, "
                f"component={component}, verdict={verdict}, "
                f"finding_id={finding_id}, asi_class={asi_class}, "
                f"atlas={atlas}, score={r.score:.2f}, "
                f"deterministic_hits={det_hits}, "
                f"success={r.success}, severity={r.severity.value}, "
                f"objective={r.indicators.get('objective', 'N/A')}, "
                f"inconclusive_reason={inconclusive_reason!r}"
            )
        attacks_fact_str = "\n".join(attacks_fact) if attacks_fact else "None"

        user_message = (
            f"Run ID: {run_id}\n"
            f"Target ID: {target_id}\n"
            f"Start: {start_time.isoformat()}\n"
            f"End: {end_time.isoformat()}\n"
            f"Factual Attack Log:\n{attacks_fact_str}\n"
        )

        try:
            sec_report: SecurityReport = self.llm.invoke_chain(
                self._report_chain, user_message, system_context=self.system_prompt
            )
            narratives = {
                "executive_summary": sec_report.executive_summary,
                "attack_campaign": sec_report.attack_campaign,
                "vulnerabilities_found": sec_report.vulnerabilities_found,
                "evidence_summary": sec_report.evidence_summary,
                "remaining_risks": sec_report.remaining_risks,
            }
        except Exception as e:
            logger.error(f"Reporter agent failed to generate narratives: {e}")
            # Fail closed: never publish a report with fabricated narrative
            # text when the real reporter model is unavailable.
            raise RuntimeError(f"reporter model unavailable: {e}") from e

        recommendations = self._generate_recommendations(attack_results)

        report = RedTeamReport(
            run_id=run_id,
            target_id=target_id,
            start_time=start_time,
            end_time=end_time,
            total_attacks=total_attacks,
            successful_attacks=successful_attacks,
            attack_results=attack_results,
            severity_distribution=severity_dist,
            success_rate=success_rate,
            recommendations=recommendations,
            assumptions=_ASSUMPTIONS,
            narratives=narratives,
        )

        logger.info(f"Generated report: {total_attacks} attacks, {success_rate:.1%} success")
        return report

    def write_markdown(self, report: RedTeamReport) -> Path:
        """Write report in Markdown format per spec structure."""
        output_file = self.output_dir / f"{report.run_id}_report.md"
        duration_s = int((report.end_time - report.start_time).total_seconds())

        # Build findings and inconclusive_attempts for the markdown sections
        findings_by_id: dict = {}
        inconclusive_list = []
        for r in report.attack_results:
            verdict = r.indicators.get("verdict", "unknown")
            if verdict in ("confirmed", "unconfirmed") and r.finding_id:
                fid = r.finding_id
                if fid not in findings_by_id:
                    findings_by_id[fid] = {
                        "finding_id": fid,
                        "verdict": verdict,
                        "verdict_path": r.indicators.get("verdict_path", ""),
                        "asi_class": r.indicators.get("asi_class", ""),
                        "atlas_technique": r.indicators.get("atlas_technique"),
                        "severity": r.severity.value,
                        "component": r.indicators.get("component", ""),
                        "strategy": r.strategy_type.value,
                        "score": r.score,
                        "threshold_used": r.score_threshold,
                        "confidence": r.indicators.get("_verdict", {}).get("confidence", "low"),
                        "deterministic_hits": r.indicators.get(
                            "deterministic_hits",
                            list(r.indicators.get("deterministic_checks", {}).keys()),
                        ),
                        "evidence_summary": (
                            r.indicators.get("evidence_summary")
                            or r.indicators.get("evidence", "")
                        ),
                        "adversarial_input_hash": r.indicators.get("adversarial_input_hash", ""),
                        "attempt_numbers": [],
                    }
                findings_by_id[fid]["attempt_numbers"].append(r.attempt_number)
            elif verdict == "inconclusive":
                inconclusive_list.append({
                    "attempt_number": r.attempt_number,
                    "strategy": r.strategy_type.value,
                    "component": r.indicators.get("component", ""),
                    "inconclusive_reason": (
                        r.indicators.get("_verdict", {}).get("inconclusive_reason", "") or ""
                    ),
                    "score": r.score,
                    "threshold_used": r.score_threshold,
                })

        confirmed_ids = {fid for fid, f in findings_by_id.items() if f["verdict"] == "confirmed"}
        unconfirmed_ids = {fid for fid, f in findings_by_id.items() if f["verdict"] == "unconfirmed"}

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"# Red Team Report: {report.run_id}\n\n")

            # Factual metrics table
            f.write("## Factual Metrics\n\n")
            f.write("| Field | Value |\n|---|---|\n")
            f.write(f"| Run ID | {report.run_id} |\n")
            f.write(f"| Target | {report.target_id} |\n")
            f.write(f"| Date | {report.start_time.strftime('%Y-%m-%d %H:%M:%S')} |\n")
            f.write(f"| Duration | {duration_s}s |\n")
            f.write(f"| Total Attacks | {report.total_attacks} |\n")
            f.write(f"| Confirmed Findings | {len(confirmed_ids)} |\n")
            f.write(f"| Unconfirmed Findings | {len(unconfirmed_ids)} |\n")
            f.write(f"| Success Rate | {report.success_rate:.1%} |\n")
            f.write("\n")

            # Per-attack evidence table
            f.write("## Per-Attack Evidence\n\n")
            f.write("| # | Strategy | Component | Verdict | Path | Score | Threshold | Det Hits | Finding ID |\n")
            f.write("|---|---|---|---|---|---|---|---|---|\n")
            for r in report.attack_results:
                det = ", ".join(r.indicators.get(
                    "deterministic_hits",
                    list(r.indicators.get("deterministic_checks", {}).keys()),
                )) or "—"
                fid = r.finding_id or "—"
                thr = getattr(r, "score_threshold", "—")
                cmp = r.indicators.get("component", "—")
                f.write(
                    f"| {r.attempt_number} "
                    f"| {r.strategy_type.value} "
                    f"| {cmp} "
                    f"| {r.indicators.get('verdict','?')} "
                    f"| {r.indicators.get('verdict_path','?')} "
                    f"| {r.score:.2f} "
                    f"| {thr} "
                    f"| {det} "
                    f"| {fid} |\n"
                )
            f.write("\n")

            # Confirmed findings (one subsection per finding_id)
            f.write("## Confirmed Findings\n\n")
            if not findings_by_id:
                f.write("No confirmed or unconfirmed findings.\n\n")
            else:
                for fid, fi in findings_by_id.items():
                    f.write(f"### Finding `{fid}`\n\n")
                    f.write(f"| Field | Value |\n|---|---|\n")
                    f.write(f"| Verdict | {fi['verdict']} |\n")
                    f.write(f"| ASI Class | {fi['asi_class']} |\n")
                    f.write(f"| Severity | {fi['severity']} |\n")
                    f.write(f"| Component | {fi['component']} |\n")
                    f.write(f"| Strategy | {fi['strategy']} |\n")
                    f.write(f"| Verdict Path | {fi['verdict_path']} |\n")
                    f.write(f"| Score | {fi['score']:.2f} |\n")
                    f.write(f"| Attempts | {fi['attempt_numbers']} |\n")
                    f.write(f"| Deterministic Hits | {fi['deterministic_hits'] or '—'} |\n")
                    f.write(f"| Input Hash | {fi['adversarial_input_hash'] or '—'} |\n")
                    if fi["evidence_summary"]:
                        f.write(f"\n**Evidence:** {fi['evidence_summary']}\n")
                    f.write("\n")

            # Inconclusive attempts
            f.write("## Inconclusive Attempts\n\n")
            if not inconclusive_list:
                f.write("None.\n\n")
            else:
                for ia in inconclusive_list:
                    f.write(
                        f"- Attempt {ia['attempt_number']}: {ia['strategy']} / {ia['component']} — "
                        f"score={ia['score']:.2f}, threshold={ia['threshold_used']}, "
                        f"reason={ia['inconclusive_reason']!r}\n"
                    )
                f.write("\n")

            # Remaining risks
            f.write("## Remaining Risks\n\n")
            f.write(f"{report.narratives.get('remaining_risks', '')}\n\n")

            # Recommendations
            f.write("## Recommendations\n\n")
            for i, rec in enumerate(report.recommendations, 1):
                f.write(f"{i}. {rec}\n")

        logger.info(f"Wrote Markdown report to {output_file}")
        return output_file

    def write_json(self, report: RedTeamReport) -> Path:
        """Write report in JSON format per spec schema."""
        output_file = self.output_dir / f"{report.run_id}_report.json"
        duration_s = int((report.end_time - report.start_time).total_seconds())

        # Group attacks by finding_id for findings[] section
        findings_by_id: dict = {}
        inconclusive_attempts = []

        for r in report.attack_results:
            verdict = r.indicators.get("verdict", "unknown")
            fid = r.finding_id

            if verdict in ("confirmed", "unconfirmed") and fid:
                if fid not in findings_by_id:
                    findings_by_id[fid] = {
                        "finding_id": fid,
                        "verdict": verdict,
                        "verdict_path": r.indicators.get("verdict_path", ""),
                        "asi_class": r.indicators.get("asi_class", ""),
                        "atlas_technique": r.indicators.get("atlas_technique"),
                        "severity": r.severity.value,
                        "component": r.indicators.get("component", ""),
                        "strategy": r.strategy_type.value,
                        "score": r.score,
                        "threshold_used": r.score_threshold,
                        "confidence": r.indicators.get("_verdict", {}).get("confidence", "low"),
                        "deterministic_hits": r.indicators.get(
                            "deterministic_hits",
                            list(r.indicators.get("deterministic_checks", {}).keys()),
                        ),
                        "evidence_summary": (
                            r.indicators.get("evidence_summary")
                            or r.indicators.get("evidence", "")
                        ),
                        "adversarial_input_hash": r.indicators.get("adversarial_input_hash", ""),
                        "attempt_numbers": [],
                    }
                findings_by_id[fid]["attempt_numbers"].append(r.attempt_number)

            elif verdict == "inconclusive":
                inconclusive_attempts.append({
                    "attempt_number": r.attempt_number,
                    "strategy": r.strategy_type.value,
                    "component": r.indicators.get("component", ""),
                    "inconclusive_reason": (
                        r.indicators.get("_verdict", {}).get("inconclusive_reason", "") or ""
                    ),
                    "score": r.score,
                    "threshold_used": r.score_threshold,
                })

        confirmed_ids = {fid for fid, f in findings_by_id.items() if f["verdict"] == "confirmed"}
        unconfirmed_ids = {fid for fid, f in findings_by_id.items() if f["verdict"] == "unconfirmed"}
        inconclusive_count = sum(
            1 for r in report.attack_results
            if r.indicators.get("verdict") == "inconclusive"
        )
        failed_count = sum(
            1 for r in report.attack_results
            if r.indicators.get("verdict") == "failed"
        )

        data = {
            "run_id": report.run_id,
            "target_id": report.target_id,
            "start_time": report.start_time.isoformat(),
            "end_time": report.end_time.isoformat(),
            "duration_seconds": duration_s,

            "verdict_summary": {
                "confirmed": len(confirmed_ids),
                "unconfirmed": len(unconfirmed_ids),
                "inconclusive": inconclusive_count,
                "failed": failed_count,
            },

            "findings": list(findings_by_id.values()),
            "inconclusive_attempts": inconclusive_attempts,

            "total_attacks": report.total_attacks,
            "successful_attacks": len(confirmed_ids),
            "success_rate": len(confirmed_ids) / report.total_attacks if report.total_attacks > 0 else 0.0,

            "assumptions": _ASSUMPTIONS,
            "recommendations": report.recommendations,
            "narratives": {k: v for k, v in report.narratives.items() if k != "assumptions"},
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Wrote JSON report to {output_file}")
        return output_file

    def _generate_recommendations(
        self,
        attack_results: List[AttackResult],
    ) -> List[str]:
        """Generate finding_id-anchored security recommendations."""
        recommendations = []
        successful = [r for r in attack_results if r.success]

        if not successful:
            recommendations.append("No confirmed attacks. Continue monitoring for new vectors.")
            return recommendations

        seen_findings: dict = {}
        for r in successful:
            fid = r.finding_id or "unknown"
            if fid in seen_findings:
                continue

            asi = r.indicators.get("asi_class", "")
            component = r.indicators.get("component", r.strategy_type.value)
            strategy = r.strategy_type.value
            recommendations.append(
                f"Remediate {component} against {strategy} "
                f"(finding {fid}, {asi})."
            )
            seen_findings[fid] = True

        return recommendations
