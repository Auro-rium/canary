from __future__ import annotations

import pytest

from cyberredteam.evaluation.release_policy import (
    CoverageInput,
    ExecutionStatus,
    GateDecision,
    GatePolicy,
    RegressionClassification,
    RegressionForPolicy,
    Severity,
    calculate_coverage,
    evaluate_gate,
)


def regression(severity: Severity) -> RegressionForPolicy:
    return RegressionForPolicy(RegressionClassification.REGRESSION, severity)


@pytest.mark.parametrize("severity", [Severity.CRITICAL, Severity.HIGH])
def test_block_on_severity_blocks_directly(severity: Severity) -> None:
    result = evaluate_gate([regression(severity)], GatePolicy())

    assert result.decision is GateDecision.BLOCK
    assert result.new_blocking_findings == 1


@pytest.mark.parametrize("severity", [Severity.MEDIUM, Severity.LOW])
def test_warn_on_severity_warns_without_blocking(severity: Severity) -> None:
    result = evaluate_gate([regression(severity)], GatePolicy())

    assert result.decision is GateDecision.WARN
    assert result.new_blocking_findings == 0
    assert result.new_nonblocking_findings == 1


def test_blocking_count_threshold_applies_only_to_blocking_severities() -> None:
    policy = GatePolicy(
        block_on=frozenset({Severity.CRITICAL}),
        warn_on=frozenset({Severity.HIGH, Severity.MEDIUM, Severity.LOW}),
        max_new_blocking_findings=2,
    )

    result = evaluate_gate([regression(Severity.HIGH)] * 3, policy)

    assert result.decision is GateDecision.WARN
    assert result.new_blocking_findings == 0
    assert result.new_nonblocking_findings == 3


def test_nonblocking_threshold_is_explicit_hard_cap() -> None:
    policy = GatePolicy(
        block_on=frozenset({Severity.CRITICAL}),
        warn_on=frozenset({Severity.HIGH, Severity.MEDIUM, Severity.LOW}),
        max_new_blocking_findings=None,
        max_new_nonblocking_findings=1,
    )

    result = evaluate_gate([regression(Severity.LOW), regression(Severity.MEDIUM)], policy)

    assert result.decision is GateDecision.BLOCK
    assert result.new_nonblocking_findings == 2


def test_known_and_resolved_findings_do_not_block() -> None:
    result = evaluate_gate(
        [
            RegressionForPolicy(RegressionClassification.KNOWN, Severity.CRITICAL),
            RegressionForPolicy(RegressionClassification.RESOLVED, Severity.HIGH),
            RegressionForPolicy(RegressionClassification.CLEAN),
        ],
        GatePolicy(),
    )

    assert result.decision is GateDecision.PASS
    assert result.known_findings == 1
    assert result.resolved_findings == 1
    assert result.clean_findings == 1


def test_indeterminate_comparison_warns_instead_of_false_pass() -> None:
    result = evaluate_gate(
        [RegressionForPolicy(RegressionClassification.INDETERMINATE)], GatePolicy()
    )

    assert result.decision is GateDecision.WARN
    assert result.indeterminate_findings == 1


def test_regression_requires_severity() -> None:
    with pytest.raises(ValueError, match="requires a severity"):
        evaluate_gate([RegressionForPolicy(RegressionClassification.REGRESSION)], GatePolicy())


def test_policy_rejects_overlapping_or_negative_configuration() -> None:
    with pytest.raises(ValueError, match="must not overlap"):
        GatePolicy(block_on=frozenset({Severity.HIGH}), warn_on=frozenset({Severity.HIGH}))
    with pytest.raises(ValueError, match="non-negative"):
        GatePolicy(max_new_blocking_findings=-1)
    with pytest.raises(ValueError, match="non-negative"):
        GatePolicy(max_new_nonblocking_findings=-1)


def test_coverage_is_independent_of_vulnerability_outcome() -> None:
    coverage = calculate_coverage(
        ["tool_misuse", "sensitive_data_exposure"],
        [
            CoverageInput("tool_misuse", ExecutionStatus.COMPLETED),
            CoverageInput("sensitive_data_exposure", ExecutionStatus.COMPLETED),
        ],
    )

    assert coverage.percentage == 100.0
    assert coverage.successful_strategies == 2
    assert coverage.completed_attack_cases == 2


def test_coverage_tracks_partial_failed_and_skipped_work() -> None:
    coverage = calculate_coverage(
        ["prompt_injection", "tool_misuse", "retrieval_poisoning"],
        [
            CoverageInput("prompt_injection", ExecutionStatus.COMPLETED),
            CoverageInput("prompt_injection", ExecutionStatus.COMPLETED),
            CoverageInput("tool_misuse", ExecutionStatus.FAILED),
            CoverageInput("retrieval_poisoning", ExecutionStatus.SKIPPED),
        ],
    )

    assert coverage.planned_attack_cases == 4
    assert coverage.attempted_attack_cases == 4
    assert coverage.completed_attack_cases == 2
    assert coverage.failed_attack_cases == 1
    assert coverage.skipped_attack_cases == 1
    assert coverage.percentage == 50.0
    assert coverage.attempted_strategies == 3
    assert coverage.successful_strategies == 1
    assert coverage.failed_strategies == 1
    assert coverage.skipped_strategies == 1


def test_planned_cases_are_not_covered_or_attempted() -> None:
    coverage = calculate_coverage(
        ["authorization_boundary"],
        [CoverageInput("authorization_boundary", ExecutionStatus.PLANNED)],
    )

    assert coverage.planned_attack_cases == 1
    assert coverage.attempted_attack_cases == 0
    assert coverage.completed_attack_cases == 0
    assert coverage.percentage == 0.0


def test_empty_test_surface_has_vacuous_full_coverage() -> None:
    coverage = calculate_coverage([], [])

    assert coverage.percentage == 100.0
    assert coverage.configured_strategies == 0


def test_required_unknown_strategy_is_rejected() -> None:
    with pytest.raises(ValueError, match="unconfigured"):
        calculate_coverage(
            ["tool_misuse"],
            [CoverageInput("sensitive_data_exposure", ExecutionStatus.COMPLETED)],
        )
