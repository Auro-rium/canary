"""Pure policy and coverage primitives for differential release security gates.

The release orchestration layer owns persistence and execution.  This module is
deliberately dependency-free so policy decisions remain deterministic, easy to
test, and safe to reuse from an API worker or a command-line integration.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping


class Severity(str, Enum):
    """Normalized severity values understood by the release gate."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RegressionClassification(str, Enum):
    """The outcome of replaying one attack case on two releases."""

    REGRESSION = "regression"
    KNOWN = "known"
    RESOLVED = "resolved"
    CLEAN = "clean"
    INDETERMINATE = "indeterminate"


class GateDecision(str, Enum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Explicit thresholds for *new* differential security regressions.

    ``max_new_blocking_findings`` applies only to regression severities in
    ``block_on``.  ``max_new_nonblocking_findings`` is an optional hard cap for
    regressions outside that set.  This intentionally avoids treating a broad
    count limit as an implicit block for every low-severity finding.
    """

    block_on: frozenset[Severity] = frozenset({Severity.CRITICAL, Severity.HIGH})
    warn_on: frozenset[Severity] = frozenset({Severity.MEDIUM, Severity.LOW})
    max_new_blocking_findings: int | None = 0
    max_new_nonblocking_findings: int | None = None

    def __post_init__(self) -> None:
        if self.block_on & self.warn_on:
            overlap = ", ".join(sorted(item.value for item in self.block_on & self.warn_on))
            raise ValueError(f"block_on and warn_on must not overlap: {overlap}")
        if self.max_new_blocking_findings is not None and self.max_new_blocking_findings < 0:
            raise ValueError("max_new_blocking_findings must be non-negative or None")
        if (
            self.max_new_nonblocking_findings is not None
            and self.max_new_nonblocking_findings < 0
        ):
            raise ValueError("max_new_nonblocking_findings must be non-negative or None")


@dataclass(frozen=True, slots=True)
class RegressionForPolicy:
    """The minimal persisted regression data needed for a policy decision."""

    classification: RegressionClassification
    severity: Severity | None = None


@dataclass(frozen=True, slots=True)
class GateEvaluation:
    decision: GateDecision
    new_blocking_findings: int
    new_nonblocking_findings: int
    known_findings: int
    resolved_findings: int
    clean_findings: int
    indeterminate_findings: int
    reasons: tuple[str, ...]


def evaluate_gate(
    regressions: Iterable[RegressionForPolicy],
    policy: GatePolicy,
) -> GateEvaluation:
    """Return the policy decision for a fully classified comparison set.

    Only ``REGRESSION`` records are new findings.  ``KNOWN`` and ``RESOLVED``
    are informational; they cannot block a candidate by themselves.
    ``INDETERMINATE`` is deliberately a warning: it prevents a false PASS when
    an equivalently replayed case did not complete or cannot be compared.
    """

    blocking = 0
    nonblocking = 0
    known = 0
    resolved = 0
    clean = 0
    indeterminate = 0

    for regression in regressions:
        if regression.classification is RegressionClassification.REGRESSION:
            if regression.severity is None:
                raise ValueError("a regression requires a severity")
            if regression.severity in policy.block_on:
                blocking += 1
            else:
                nonblocking += 1
        elif regression.classification is RegressionClassification.KNOWN:
            known += 1
        elif regression.classification is RegressionClassification.RESOLVED:
            resolved += 1
        elif regression.classification is RegressionClassification.CLEAN:
            clean += 1
        elif regression.classification is RegressionClassification.INDETERMINATE:
            indeterminate += 1
        else:  # Defensive guard for enum expansion.
            raise ValueError(f"unknown regression classification: {regression.classification!r}")

    reasons: list[str] = []
    if blocking:
        reasons.append("new regression matches block_on severity")
    if (
        policy.max_new_blocking_findings is not None
        and blocking > policy.max_new_blocking_findings
    ):
        reasons.append("new blocking regression threshold exceeded")
    if (
        policy.max_new_nonblocking_findings is not None
        and nonblocking > policy.max_new_nonblocking_findings
    ):
        reasons.append("new nonblocking regression threshold exceeded")

    if reasons:
        decision = GateDecision.BLOCK
    elif nonblocking:
        decision = GateDecision.WARN
        reasons.append("new nonblocking regression")
    elif indeterminate:
        decision = GateDecision.WARN
        reasons.append("incomplete or indeterminate comparison")
    else:
        decision = GateDecision.PASS

    return GateEvaluation(
        decision=decision,
        new_blocking_findings=blocking,
        new_nonblocking_findings=nonblocking,
        known_findings=known,
        resolved_findings=resolved,
        clean_findings=clean,
        indeterminate_findings=indeterminate,
        reasons=tuple(reasons),
    )


class ExecutionStatus(str, Enum):
    """Terminal and non-terminal states for required attack executions."""

    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class CoverageInput:
    """One required execution with the strategy it belongs to."""

    strategy: str
    status: ExecutionStatus
    required: bool = True


@dataclass(frozen=True, slots=True)
class Coverage:
    """Coverage of the configured attack surface, independent of findings."""

    configured_strategies: int
    attempted_strategies: int
    successful_strategies: int
    failed_strategies: int
    skipped_strategies: int
    planned_attack_cases: int
    attempted_attack_cases: int
    completed_attack_cases: int
    failed_attack_cases: int
    skipped_attack_cases: int
    percentage: float


def calculate_coverage(
    configured_strategies: Iterable[str],
    executions: Iterable[CoverageInput],
) -> Coverage:
    """Calculate true execution coverage for the configured test surface.

    The denominator is required, planned work. A completed safe attack counts
    exactly like a completed vulnerable attack because coverage answers whether
    the test ran, not whether it produced a finding.
    """

    configured = frozenset(configured_strategies)
    execution_items = tuple(executions)
    unknown = sorted(
        {item.strategy for item in execution_items if item.required and item.strategy not in configured}
    )
    if unknown:
        raise ValueError(f"required executions use unconfigured strategies: {', '.join(unknown)}")

    by_strategy: Mapping[str, tuple[CoverageInput, ...]] = {
        strategy: tuple(item for item in execution_items if item.required and item.strategy == strategy)
        for strategy in configured
    }
    required = tuple(item for item in execution_items if item.required)
    planned = len(required)
    completed = sum(item.status is ExecutionStatus.COMPLETED for item in required)
    failed = sum(item.status is ExecutionStatus.FAILED for item in required)
    skipped = sum(item.status is ExecutionStatus.SKIPPED for item in required)
    attempted = sum(
        item.status
        in {
            ExecutionStatus.RUNNING,
            ExecutionStatus.COMPLETED,
            ExecutionStatus.FAILED,
            ExecutionStatus.SKIPPED,
        }
        for item in required
    )

    attempted_strategies = sum(
        any(item.status is not ExecutionStatus.PLANNED for item in strategy_items)
        for strategy_items in by_strategy.values()
    )
    successful_strategies = sum(
        bool(strategy_items)
        and all(item.status is ExecutionStatus.COMPLETED for item in strategy_items)
        for strategy_items in by_strategy.values()
    )
    failed_strategies = sum(
        any(item.status is ExecutionStatus.FAILED for item in strategy_items)
        for strategy_items in by_strategy.values()
    )
    skipped_strategies = sum(
        bool(strategy_items)
        and all(item.status is ExecutionStatus.SKIPPED for item in strategy_items)
        for strategy_items in by_strategy.values()
    )
    percentage = 100.0 if planned == 0 else round((completed / planned) * 100, 2)

    return Coverage(
        configured_strategies=len(configured),
        attempted_strategies=attempted_strategies,
        successful_strategies=successful_strategies,
        failed_strategies=failed_strategies,
        skipped_strategies=skipped_strategies,
        planned_attack_cases=planned,
        attempted_attack_cases=attempted,
        completed_attack_cases=completed,
        failed_attack_cases=failed,
        skipped_attack_cases=skipped,
        percentage=percentage,
    )
