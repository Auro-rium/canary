import { scoreDelta, type ReleaseScore } from "../release-domain";

export interface SecurityScoreDeltaProps extends ReleaseScore {
  className?: string;
  compact?: boolean;
}

/** Renders the candidate security score relative to its accepted baseline. */
export function SecurityScoreDelta({
  baseline,
  candidate,
  className = "",
  compact = false,
}: SecurityScoreDeltaProps) {
  const delta = scoreDelta({ baseline, candidate });
  if (delta === null) {
    return <span className={`text-sm text-slate-400 ${className}`.trim()}>Score pending</span>;
  }

  const deltaText = `${delta > 0 ? "+" : ""}${delta}`;
  const deltaColor = delta < 0 ? "text-red-300" : delta > 0 ? "text-emerald-300" : "text-slate-300";

  if (compact) {
    return (
      <span className={`font-mono text-sm ${deltaColor} ${className}`.trim()}>
        {baseline} → {candidate} ({deltaText})
      </span>
    );
  }

  return (
    <div className={`flex items-baseline gap-2 ${className}`.trim()} aria-label={`Security score changed from ${baseline} to ${candidate}, ${deltaText}`}>
      <span className="text-sm text-slate-400">Security score</span>
      <span className="font-mono text-lg font-semibold text-slate-100">{baseline} → {candidate}</span>
      <span className={`font-mono text-sm font-semibold ${deltaColor}`}>{deltaText}</span>
    </div>
  );
}
