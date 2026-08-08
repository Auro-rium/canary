"""Focused deterministic tests for the standalone differential engine."""

import pytest

from cyberredteam.evaluation.differential import (
    AttackCase,
    AttackExecution,
    EvaluatorVerdict,
    RegressionClassification,
    Severity,
    calculate_security_score,
    classify_attack_case,
    compare_release_executions,
    stable_attack_case_id,
    stable_regression_id,
)

CASE = "case-tool-misuse"


def safe(case_id: str = CASE) -> AttackExecution:
    return AttackExecution(case_id, EvaluatorVerdict.SAFE, confidence=0.99)


def vulnerable(
    case_id: str = CASE, severity: Severity = Severity.HIGH, *, confirmed: bool = True
) -> AttackExecution:
    return AttackExecution(
        case_id,
        EvaluatorVerdict.VULNERABLE,
        severity=severity,
        confidence=0.98,
        deterministic_signals=("unsafe_tool_action",),
        confirmed=confirmed,
    )


@pytest.mark.parametrize(
    ("baseline", "candidate", "expected", "reason"),
    [
        (safe(), vulnerable(), RegressionClassification.REGRESSION, "candidate_newly_vulnerable"),
        (vulnerable(), vulnerable(), RegressionClassification.KNOWN, "vulnerability_preexisting_in_baseline"),
        (vulnerable(), safe(), RegressionClassification.RESOLVED, "candidate_resolved_baseline_vulnerability"),
        (safe(), safe(), RegressionClassification.CLEAN, "both_versions_safe"),
    ],
)
def test_classifies_each_conclusive_baseline_candidate_outcome(
    baseline: AttackExecution,
    candidate: AttackExecution,
    expected: RegressionClassification,
    reason: str,
) -> None:
    result = classify_attack_case(
        project_id="companybot",
        baseline_release_id="baseline",
        candidate_release_id="candidate",
        attack_case_id=CASE,
        baseline_execution=baseline,
        candidate_execution=candidate,
    )

    assert result.classification is expected
    assert result.reason.code == reason
    assert result.regression_id == stable_regression_id("companybot", CASE, "baseline", "candidate")


def test_unconfirmed_or_missing_execution_is_indeterminate() -> None:
    unconfirmed = vulnerable(confirmed=False)
    result = classify_attack_case(
        project_id="project",
        baseline_release_id="base",
        candidate_release_id="candidate",
        attack_case_id=CASE,
        baseline_execution=safe(),
        candidate_execution=unconfirmed,
    )
    missing = classify_attack_case(
        project_id="project",
        baseline_release_id="base",
        candidate_release_id="candidate",
        attack_case_id=CASE,
        baseline_execution=None,
        candidate_execution=safe(),
    )

    assert result.classification is RegressionClassification.INDETERMINATE
    assert missing.classification is RegressionClassification.INDETERMINATE
    assert result.reason.code == "comparison_not_conclusive"


def test_attack_case_identity_is_canonical_for_metadata_order() -> None:
    first = AttackCase("project", "tool_misuse", "calculator", "run calc", {"b": 2, "a": 1})
    second = AttackCase("project", "tool_misuse", "calculator", "run calc", {"a": 1, "b": 2})

    assert first.attack_case_id == second.attack_case_id
    assert first.attack_case_id == stable_attack_case_id(
        "project", "tool_misuse", "calculator", "run calc", {"a": 1, "b": 2}
    )


def test_scores_unique_confirmed_cases_and_floors_at_zero() -> None:
    score = calculate_security_score(
        [
            vulnerable("critical", Severity.CRITICAL),
            vulnerable("high", Severity.HIGH),
            vulnerable("low", Severity.LOW),
            vulnerable("high", Severity.MEDIUM),  # duplicate cannot reduce the worse penalty
            vulnerable("ignored", Severity.CRITICAL, confirmed=False),
        ]
    )
    exhausted = calculate_security_score(
        [vulnerable(f"critical-{index}", Severity.CRITICAL) for index in range(4)]
    )

    assert score.score == 49
    assert score.vulnerable_case_count == 3
    assert exhausted.score == 0


def test_release_comparison_is_independent_of_parallel_completion_order() -> None:
    baseline = [safe("z"), vulnerable("a", Severity.MEDIUM)]
    candidate = [safe("z"), vulnerable("a", Severity.MEDIUM), vulnerable("m", Severity.HIGH)]

    forward = compare_release_executions(
        project_id="project",
        baseline_release_id="base",
        candidate_release_id="candidate",
        baseline_executions=baseline,
        candidate_executions=candidate,
    )
    reverse = compare_release_executions(
        project_id="project",
        baseline_release_id="base",
        candidate_release_id="candidate",
        baseline_executions=list(reversed(baseline)),
        candidate_executions=list(reversed(candidate)),
    )

    assert [item.attack_case_id for item in forward.regressions] == ["a", "m", "z"]
    assert forward.regressions == reverse.regressions
    assert forward.baseline_score.score == 95
    assert forward.candidate_score.score == 80
    assert forward.score_delta == -15
    assert forward.classification_counts[RegressionClassification.KNOWN] == 1
    assert forward.classification_counts[RegressionClassification.INDETERMINATE] == 1


def test_duplicate_execution_and_invalid_input_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate baseline"):
        compare_release_executions(
            project_id="project",
            baseline_release_id="base",
            candidate_release_id="candidate",
            baseline_executions=[safe(), safe()],
            candidate_executions=[safe()],
        )
    with pytest.raises(ValueError, match="vulnerable executions require"):
        AttackExecution(CASE, EvaluatorVerdict.VULNERABLE, confirmed=True)
    with pytest.raises(ValueError, match="confidence"):
        AttackExecution(CASE, EvaluatorVerdict.SAFE, confidence=1.1)
