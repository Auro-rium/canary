/**
 * Presentation-facing release types.
 *
 * These are deliberately independent from the transport client so existing
 * pages can adopt the release experience incrementally while API contracts
 * settle.  Map API results to these types at the page boundary.
 */
export type ReleaseDecision = "pass" | "warn" | "block" | null;

export type RegressionClassification =
  | "regression"
  | "known"
  | "resolved"
  | "clean"
  | "indeterminate";

export interface ReleaseCoverage {
  configuredStrategies: number;
  attemptedStrategies: number;
  successfulStrategies: number;
  failedStrategies: number;
  skippedStrategies: number;
  plannedAttackCases: number;
  attemptedAttackCases: number;
  completedAttackCases: number;
}

export interface ReleaseRegressionCounts {
  regressions: number;
  known: number;
  resolved: number;
  clean?: number;
  indeterminate?: number;
}

export interface ReleaseScore {
  baseline: number | null;
  candidate: number | null;
}

export interface ReleaseRegression {
  regression_id: string;
  attack_case_id: string;
  classification: RegressionClassification;
  severity: string | null;
  baseline_verdict: string | null;
  candidate_verdict: string | null;
  baseline_evidence: Record<string, unknown>;
  candidate_evidence: Record<string, unknown>;
  reason: string;
}

export const decisionLabel = (decision: ReleaseDecision): string => {
  if (decision === "pass") return "PASS";
  if (decision === "warn") return "WARN";
  if (decision === "block") return "BLOCK";
  return "PENDING";
};

/** Percentage of required cases whose execution reached a terminal result. */
export const coveragePercentage = (coverage: ReleaseCoverage): number => {
  if (coverage.plannedAttackCases === 0) return 0;
  return Math.min(
    100,
    Math.max(0, (coverage.completedAttackCases / coverage.plannedAttackCases) * 100),
  );
};

export const scoreDelta = (score: ReleaseScore): number | null => {
  if (score.baseline === null || score.candidate === null) return null;
  return score.candidate - score.baseline;
};
