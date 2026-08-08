import type { ReleaseRegressionCounts } from "../release-domain";

export interface RegressionCountsProps {
  counts: ReleaseRegressionCounts;
  className?: string;
}

const metricClass = {
  regressions: "text-red-300",
  known: "text-amber-300",
  resolved: "text-emerald-300",
  clean: "text-slate-300",
  indeterminate: "text-slate-400",
} as const;

/** Small release-summary counters with terminology matching differential classifications. */
export function RegressionCounts({ counts, className = "" }: RegressionCountsProps) {
  const metrics = [
    ["New regressions", counts.regressions, "regressions"],
    ["Known", counts.known, "known"],
    ["Resolved", counts.resolved, "resolved"],
    ...(counts.clean === undefined ? [] : [["Clean", counts.clean, "clean"] as const]),
    ...(counts.indeterminate === undefined
      ? []
      : [["Indeterminate", counts.indeterminate, "indeterminate"] as const]),
  ] as const;

  return (
    <dl className={`flex flex-wrap gap-x-5 gap-y-2 ${className}`.trim()}>
      {metrics.map(([label, value, key]) => (
        <div key={key} className="flex items-baseline gap-1.5">
          <dt className="text-xs text-slate-400">{label}</dt>
          <dd className={`font-mono text-sm font-semibold ${metricClass[key]}`}>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
