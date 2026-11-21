const clamp = (value: number) => (Number.isFinite(value) ? Math.min(1, Math.max(0, value)) : 0)
export const pct = (value: number) => `${(clamp(value) * 100).toFixed(0)}%`

/** Geometry of a success-rate marker and its 95% confidence band, as percentages of the track. */
export function ciGeometry(rate: number, low: number, high: number) {
  const a = clamp(low)
  const b = clamp(high)
  const lo = Math.min(a, b)
  const hi = Math.max(a, b)
  return { left: lo * 100, width: (hi - lo) * 100, marker: clamp(rate) * 100 }
}

/** Success rate (marker) with its 95% confidence interval (band). Numbers are in the accessible name. */
export function CIBar({ rate, low, high, className = 'w-40' }: { rate: number; low: number; high: number; className?: string }) {
  const g = ciGeometry(rate, low, high)
  return (
    <div className={`relative h-3 rounded-sm bg-raised ring-1 ring-line ${className}`} role="img"
      aria-label={`${pct(rate)} success rate, 95% confidence interval ${pct(low)} to ${pct(high)}`}>
      <div className="absolute inset-y-0 rounded-sm bg-danger/35" style={{ left: `${g.left}%`, width: `${g.width}%` }} />
      <div className="absolute -inset-y-0.5 w-[3px] -translate-x-1/2 rounded-sm bg-danger" style={{ left: `${g.marker}%` }} />
    </div>
  )
}
