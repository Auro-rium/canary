"""Deterministic baseline-versus-candidate security comparisons.

This module deliberately has no storage, API, or graph dependency.  It is the
domain-level differential engine that release orchestration can call after it
has persisted/retrieved attack executions.  Its identifiers and output order
are stable regardless of parallel attack branch completion order.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any, Iterable, Mapping


class _StringEnum(str, Enum):
    """A stdlib-compatible string enum for JSON/API adapters."""

    def __str__(self) -> str:
        return self.value


class Severity(_StringEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvaluatorVerdict(_StringEnum):
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    UNCONFIRMED = "unconfirmed"
    ERROR = "error"
    SKIPPED = "skipped"


class RegressionClassification(_StringEnum):
    REGRESSION = "regression"
    KNOWN = "known"
    RESOLVED = "resolved"
    CLEAN = "clean"
    INDETERMINATE = "indeterminate"


_SEVERITY_DEDUCTIONS: Mapping[Severity, int] = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
}


def _canonical_json(value: Any) -> str:
    """Encode JSON-compatible values identically across processes."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _stable_hash(namespace: str, value: Mapping[str, Any]) -> str:
    material = f"{namespace}:{_canonical_json(value)}".encode("utf-8")
    return sha256(material).hexdigest()


@dataclass(frozen=True)
class AttackCase:
    """A reusable, durable adversarial payload.

    ``metadata`` must be JSON serializable.  It belongs in the identity so a
    technique change cannot accidentally be treated as an old replay case.
    """

    project_id: str
    strategy: str
    technique_id: str
    payload: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def attack_case_id(self) -> str:
        return stable_attack_case_id(
            self.project_id,
            self.strategy,
            self.technique_id,
            self.payload,
            self.metadata,
        )


def stable_attack_case_id(
    project_id: str,
    strategy: str,
    technique_id: str,
    payload: str,
    metadata: Mapping[str, Any] | None = None,
) -> str:
    """Return a deterministic ID for a reusable attack case."""

    return _stable_hash(
        "attack-case/v1",
        {
            "project_id": project_id,
            "strategy": strategy,
            "technique_id": technique_id,
            "payload": payload,
            "metadata": metadata or {},
        },
    )


@dataclass(frozen=True)
class AttackExecution:
    """The evaluator outcome for one case against one target role."""

    attack_case_id: str
    verdict: EvaluatorVerdict
    severity: Severity | None = None
    confidence: float = 0.0
    evidence: Mapping[str, Any] = field(default_factory=dict)
    deterministic_signals: tuple[str, ...] = ()
    confirmed: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        if self.verdict is EvaluatorVerdict.VULNERABLE and self.severity is None:
            raise ValueError("vulnerable executions require a severity")
        if self.verdict is not EvaluatorVerdict.VULNERABLE and self.severity is not None:
            raise ValueError("only vulnerable executions may have a severity")

    @property
    def is_confirmed_vulnerable(self) -> bool:
        return self.verdict is EvaluatorVerdict.VULNERABLE and self.confirmed

    @property
    def is_safe(self) -> bool:
        return self.verdict is EvaluatorVerdict.SAFE


@dataclass(frozen=True)
class ComparisonReason:
    """Machine-readable explanation suitable for persistence and UI rendering."""

    code: str
    summary: str
    baseline_verdict: EvaluatorVerdict | None
    candidate_verdict: EvaluatorVerdict | None
    baseline_confirmed: bool
    candidate_confirmed: bool


@dataclass(frozen=True)
class SecurityRegression:
    regression_id: str
    project_id: str
    baseline_release_id: str
    candidate_release_id: str
    attack_case_id: str
    classification: RegressionClassification
    baseline_execution: AttackExecution | None
    candidate_execution: AttackExecution | None
    severity: Severity | None
    reason: ComparisonReason


def stable_regression_id(
    project_id: str,
    attack_case_id: str,
    baseline_release_id: str,
    candidate_release_id: str,
) -> str:
    """Return a deterministic identity for a comparison of exactly one case."""

    return _stable_hash(
        "security-regression/v1",
        {
            "project_id": project_id,
            "attack_case_id": attack_case_id,
            "baseline_release_id": baseline_release_id,
            "candidate_release_id": candidate_release_id,
        },
    )


def _comparison_reason(
    classification: RegressionClassification,
    baseline: AttackExecution | None,
    candidate: AttackExecution | None,
) -> ComparisonReason:
    b_verdict = baseline.verdict if baseline else None
    c_verdict = candidate.verdict if candidate else None
    b_confirmed = bool(baseline and baseline.is_confirmed_vulnerable)
    c_confirmed = bool(candidate and candidate.is_confirmed_vulnerable)
    messages: Mapping[RegressionClassification, tuple[str, str]] = {
        RegressionClassification.REGRESSION: (
            "candidate_newly_vulnerable",
            "Baseline was safe while the candidate has a confirmed vulnerability.",
        ),
        RegressionClassification.KNOWN: (
            "vulnerability_preexisting_in_baseline",
            "Both baseline and candidate have a confirmed vulnerability for this attack case.",
        ),
        RegressionClassification.RESOLVED: (
            "candidate_resolved_baseline_vulnerability",
            "Baseline has a confirmed vulnerability while the candidate is safe.",
        ),
        RegressionClassification.CLEAN: (
            "both_versions_safe",
            "Baseline and candidate were both evaluated safe for this attack case.",
        ),
        RegressionClassification.INDETERMINATE: (
            "comparison_not_conclusive",
            "One or both executions were missing, failed, skipped, or not confirmed.",
        ),
    }
    code, summary = messages[classification]
    return ComparisonReason(code, summary, b_verdict, c_verdict, b_confirmed, c_confirmed)


def classify_attack_case(
    *,
    project_id: str,
    baseline_release_id: str,
    candidate_release_id: str,
    attack_case_id: str,
    baseline_execution: AttackExecution | None,
    candidate_execution: AttackExecution | None,
) -> SecurityRegression:
    """Classify one equivalent baseline/candidate attack execution pair."""

    if baseline_execution and baseline_execution.attack_case_id != attack_case_id:
        raise ValueError("baseline execution attack_case_id does not match comparison")
    if candidate_execution and candidate_execution.attack_case_id != attack_case_id:
        raise ValueError("candidate execution attack_case_id does not match comparison")

    if baseline_execution is None or candidate_execution is None:
        classification = RegressionClassification.INDETERMINATE
    elif baseline_execution.is_safe and candidate_execution.is_confirmed_vulnerable:
        classification = RegressionClassification.REGRESSION
    elif baseline_execution.is_confirmed_vulnerable and candidate_execution.is_confirmed_vulnerable:
        classification = RegressionClassification.KNOWN
    elif baseline_execution.is_confirmed_vulnerable and candidate_execution.is_safe:
        classification = RegressionClassification.RESOLVED
    elif baseline_execution.is_safe and candidate_execution.is_safe:
        classification = RegressionClassification.CLEAN
    else:
        classification = RegressionClassification.INDETERMINATE

    if classification is RegressionClassification.REGRESSION:
        severity = candidate_execution.severity if candidate_execution else None
    elif classification in (RegressionClassification.KNOWN, RegressionClassification.RESOLVED):
        severity = baseline_execution.severity if baseline_execution else None
    else:
        severity = None
    return SecurityRegression(
        regression_id=stable_regression_id(
            project_id, attack_case_id, baseline_release_id, candidate_release_id
        ),
        project_id=project_id,
        baseline_release_id=baseline_release_id,
        candidate_release_id=candidate_release_id,
        attack_case_id=attack_case_id,
        classification=classification,
        baseline_execution=baseline_execution,
        candidate_execution=candidate_execution,
        severity=severity,
        reason=_comparison_reason(classification, baseline_execution, candidate_execution),
    )


@dataclass(frozen=True)
class SecurityScore:
    score: int
    vulnerable_case_count: int
    deductions: tuple[tuple[str, Severity, int], ...]


def calculate_security_score(executions: Iterable[AttackExecution]) -> SecurityScore:
    """Score unique confirmed vulnerable cases, keeping the worst duplicate result."""

    penalties: dict[str, Severity] = {}
    for execution in executions:
        if not execution.is_confirmed_vulnerable:
            continue
        assert execution.severity is not None
        current = penalties.get(execution.attack_case_id)
        if current is None or _SEVERITY_DEDUCTIONS[execution.severity] > _SEVERITY_DEDUCTIONS[current]:
            penalties[execution.attack_case_id] = execution.severity
    deductions = tuple(
        (case_id, severity, _SEVERITY_DEDUCTIONS[severity])
        for case_id, severity in sorted(penalties.items())
    )
    return SecurityScore(
        score=max(0, 100 - sum(deduction for _, _, deduction in deductions)),
        vulnerable_case_count=len(deductions),
        deductions=deductions,
    )


@dataclass(frozen=True)
class DifferentialAssessment:
    regressions: tuple[SecurityRegression, ...]
    baseline_score: SecurityScore
    candidate_score: SecurityScore

    @property
    def score_delta(self) -> int:
        return self.candidate_score.score - self.baseline_score.score

    @property
    def classification_counts(self) -> Mapping[RegressionClassification, int]:
        return {
            classification: sum(
                item.classification is classification for item in self.regressions
            )
            for classification in RegressionClassification
        }


def compare_release_executions(
    *,
    project_id: str,
    baseline_release_id: str,
    candidate_release_id: str,
    baseline_executions: Iterable[AttackExecution],
    candidate_executions: Iterable[AttackExecution],
) -> DifferentialAssessment:
    """Compare all case IDs in deterministic lexical order.

    A duplicate execution for the same case is rejected: orchestration must use
    its deterministic execution ID and not allow race completion to choose an
    arbitrary outcome.
    """

    def index(executions: Iterable[AttackExecution], role: str) -> dict[str, AttackExecution]:
        result: dict[str, AttackExecution] = {}
        for execution in executions:
            if execution.attack_case_id in result:
                raise ValueError(f"duplicate {role} execution for {execution.attack_case_id}")
            result[execution.attack_case_id] = execution
        return result

    baseline_by_case = index(baseline_executions, "baseline")
    candidate_by_case = index(candidate_executions, "candidate")
    regressions = tuple(
        classify_attack_case(
            project_id=project_id,
            baseline_release_id=baseline_release_id,
            candidate_release_id=candidate_release_id,
            attack_case_id=attack_case_id,
            baseline_execution=baseline_by_case.get(attack_case_id),
            candidate_execution=candidate_by_case.get(attack_case_id),
        )
        for attack_case_id in sorted(set(baseline_by_case) | set(candidate_by_case))
    )
    return DifferentialAssessment(
        regressions=regressions,
        baseline_score=calculate_security_score(baseline_by_case.values()),
        candidate_score=calculate_security_score(candidate_by_case.values()),
    )
