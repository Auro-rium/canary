import { coveragePercentage, type ReleaseCoverage } from "../release-domain";

export interface CoverageSummaryProps {
  coverage: ReleaseCoverage;
  className?: string;
  compact?: boolean;
}

/** Reports executed test surface; it never treats vulnerability count as coverage. */
export function CoverageSummary({ coverage, className = "", compact = false }: CoverageSummaryProps) {
  const percentage = coveragePercentage(coverage);
  const summary = `${coverage.completedAttackCases}/${coverage.plannedAttackCases} attack cases completed`;

  if (compact) {
    return (
      <span className={`font-mono text-sm text-slate-200 ${className}`.trim()} aria-label={`Coverage: ${percentage.toFixed(0)} percent, ${summary}`}>
        {percentage.toFixed(0)}% coverage
      </span>
    );
  }

  return (
    <section className={`space-y-2 ${className}`.trim()} aria-label="Security test coverage">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-sm text-slate-400">Coverage</span>
        <span className="font-mono text-lg font-semibold text-slate-100">{percentage.toFixed(0)}%</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-slate-800" aria-hidden="true">
        <div className="h-full rounded-full bg-cyan-400 transition-[width]" style={{ width: `${percentage}%` }} />
      </div>
      <p className="text-xs text-slate-400">
        {summary} · {coverage.successfulStrategies}/{coverage.configuredStrategies} strategies completed
        {coverage.failedStrategies > 0 ? ` · ${coverage.failedStrategies} failed` : ""}
        {coverage.skippedStrategies > 0 ? ` · ${coverage.skippedStrategies} skipped` : ""}
      </p>
    </section>
  );
}
