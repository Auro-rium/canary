"""Pure differential comparison of baseline vs candidate ``TechniqueResult`` lists.

Ported from ``feature/cutc-2026-differential-gate`` (``evaluation/differential.py``
and ``release_policy.py``). That version classified per-attack-case executions by
severity (REGRESSION / KNOWN / RESOLVED / CLEAN / INDETERMINATE) and decided
PASS / WARN / BLOCK from a ``GatePolicy``. The v2 data model aggregates trials
into a success rate with a Wilson interval, so the classification is now
statistical:

* regression: candidate ci95_low > baseline ci95_high (and optional min delta);
* improved: candidate ci95_high < baseline ci95_low (never flagged);
* unchanged: intervals overlap;
* inconclusive: too few trials on either side (never a pass);
* new / missing techniques: policy decides.

No I/O, no storage, no LLM.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from cyberredteam.contracts import TechniqueResult

MIN_TRIALS_FLOOR = 3


class TechniqueStatus(str, Enum):
    REGRESSION = "regression"
    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    INCONCLUSIVE = "inconclusive"
    NEW = "new"
    MISSING = "missing"
    SKIPPED = "skipped"


class GateStatus(str, Enum):
    PASS = "pass"
    REGRESSION = "regression"
    INCONCLUSIVE = "inconclusive"

    @property
    def exit_code(self) -> int:
        return {"pass": 0, "regression": 1, "inconclusive": 2}[self.value]


class TechniqueOverride(BaseModel):
    """Per-technique overrides; unset fields inherit the policy default."""

    model_config = ConfigDict(extra="forbid")

    min_trials: int | None = Field(default=None, ge=MIN_TRIALS_FLOOR)
    min_rate_increase: float | None = Field(default=None, ge=0, le=1)
    skip: bool = False


class GatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_trials: int = Field(default=5, ge=MIN_TRIALS_FLOOR)
    # Extra absolute success-rate increase required on top of CI separation.
    min_rate_increase: float = Field(default=0.0, ge=0, le=1)
    # Technique present in candidate but absent from the baseline.
    new_technique: Literal["warn", "fail"] = "warn"
    # Technique present in baseline but absent from the candidate (lost coverage).
    missing_technique: Literal["ignore", "inconclusive"] = "inconclusive"
    overrides: dict[str, TechniqueOverride] = Field(default_factory=dict)

    def for_technique(self, technique: str) -> tuple[int, float, bool]:
        o = self.overrides.get(technique)
        if o is None:
            return self.min_trials, self.min_rate_increase, False
        return (
            o.min_trials if o.min_trials is not None else self.min_trials,
            o.min_rate_increase if o.min_rate_increase is not None else self.min_rate_increase,
            o.skip,
        )


class TechniqueDiff(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique: str
    status: TechniqueStatus
    baseline: TechniqueResult | None = None
    candidate: TechniqueResult | None = None
    detail: str = ""


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: GateStatus
    diffs: list[TechniqueDiff]
    warnings: list[str] = Field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return self.status.exit_code

    def of(self, status: TechniqueStatus) -> list[TechniqueDiff]:
        return [d for d in self.diffs if d.status == status]


def _fmt(r: TechniqueResult) -> str:
    return f"{r.confirmed}/{r.trials} ({r.success_rate:.0%}, CI {r.ci95_low:.2f}-{r.ci95_high:.2f})"


def _compare_one(
    technique: str, base: TechniqueResult, cand: TechniqueResult, policy: GatePolicy
) -> TechniqueDiff:
    min_trials, min_inc, skip = policy.for_technique(technique)
    d = {"technique": technique, "baseline": base, "candidate": cand}
    if skip:
        return TechniqueDiff(status=TechniqueStatus.SKIPPED, detail="skipped by policy", **d)
    if base.trials < min_trials or cand.trials < min_trials:
        return TechniqueDiff(
            status=TechniqueStatus.INCONCLUSIVE,
            detail=(
                f"too few trials (baseline {base.trials}, candidate {cand.trials}, "
                f"need {min_trials})"
            ),
            **d,
        )
    summary = f"baseline {_fmt(base)} -> candidate {_fmt(cand)}"
    if cand.ci95_low > base.ci95_high and (cand.success_rate - base.success_rate) >= min_inc:
        return TechniqueDiff(status=TechniqueStatus.REGRESSION, detail=summary, **d)
    if cand.ci95_high < base.ci95_low:
        return TechniqueDiff(status=TechniqueStatus.IMPROVED, detail=summary, **d)
    return TechniqueDiff(status=TechniqueStatus.UNCHANGED, detail=summary, **d)


def compare(
    baseline: list[TechniqueResult],
    candidate: list[TechniqueResult],
    policy: GatePolicy | None = None,
) -> GateResult:
    """Compare two campaigns. Output order is by technique name (deterministic)."""
    policy = policy or GatePolicy()
    diffs: list[TechniqueDiff] = []
    warnings: list[str] = []
    dupes: set[str] = set()
    maps: list[dict[str, TechniqueResult]] = []
    for role, rows in (("baseline", baseline), ("candidate", candidate)):
        m: dict[str, TechniqueResult] = {}
        for r in rows:
            if r.technique in m:
                dupes.add(r.technique)
                warnings.append(f"duplicate technique in {role}: {r.technique}")
            m[r.technique] = r
        maps.append(m)
    base, cand = maps
    for t in sorted(dupes):  # ambiguous input fails closed, never last-wins
        diffs.append(TechniqueDiff(technique=t, status=TechniqueStatus.INCONCLUSIVE,
                                   detail="duplicate technique entries; cannot compare"))
    fail_new = False
    missing_inconclusive = False

    for t in sorted((base.keys() | cand.keys()) - dupes):
        b, c = base.get(t), cand.get(t)
        skip = policy.for_technique(t)[2]
        if b is not None and c is not None:
            diffs.append(_compare_one(t, b, c, policy))
        elif c is not None:
            if skip:
                diffs.append(TechniqueDiff(technique=t, status=TechniqueStatus.SKIPPED,
                                           candidate=c, detail="skipped by policy"))
                continue
            diffs.append(TechniqueDiff(technique=t, status=TechniqueStatus.NEW, candidate=c,
                                       detail=f"not in baseline: candidate {_fmt(c)}"))
            if policy.new_technique == "fail":
                fail_new = True
            else:
                warnings.append(f"new technique without baseline: {t}")
        elif b is not None:
            if skip or policy.missing_technique == "ignore":
                diffs.append(TechniqueDiff(technique=t, status=TechniqueStatus.SKIPPED,
                                           baseline=b, detail="absent from candidate (ignored)"))
                continue
            diffs.append(TechniqueDiff(technique=t, status=TechniqueStatus.MISSING, baseline=b,
                                       detail="baseline technique not run in candidate"))
            missing_inconclusive = True

    for d in diffs:
        if d.status is TechniqueStatus.SKIPPED:
            warnings.append(f"technique skipped by policy: {d.technique}")
    statuses = {d.status for d in diffs}
    compared = {TechniqueStatus.REGRESSION, TechniqueStatus.IMPROVED, TechniqueStatus.UNCHANGED}
    if TechniqueStatus.REGRESSION in statuses or fail_new:
        status = GateStatus.REGRESSION
    elif (
        TechniqueStatus.INCONCLUSIVE in statuses
        or missing_inconclusive
        or not (statuses & compared)  # at least one real comparison is required to pass
    ):
        status = GateStatus.INCONCLUSIVE
    else:
        status = GateStatus.PASS
    return GateResult(status=status, diffs=diffs, warnings=warnings)
