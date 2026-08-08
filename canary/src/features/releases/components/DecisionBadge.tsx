import { decisionLabel, type ReleaseDecision } from "../release-domain";

const decisionClasses: Record<Exclude<ReleaseDecision, null>, string> = {
  pass: "border-emerald-400/40 bg-emerald-400/10 text-emerald-300",
  warn: "border-amber-400/40 bg-amber-400/10 text-amber-300",
  block: "border-red-400/40 bg-red-400/10 text-red-300",
};

export interface DecisionBadgeProps {
  decision: ReleaseDecision;
  className?: string;
}

/** Compact, accessible status treatment for a release decision. */
export function DecisionBadge({ decision, className = "" }: DecisionBadgeProps) {
  const palette = decision ? decisionClasses[decision] : "border-slate-500/40 bg-slate-500/10 text-slate-300";

  return (
    <span
      aria-label={`Release decision: ${decisionLabel(decision)}`}
      className={`inline-flex items-center rounded border px-2 py-0.5 font-mono text-xs font-semibold tracking-wider ${palette} ${className}`.trim()}
    >
      {decisionLabel(decision)}
    </span>
  );
}
