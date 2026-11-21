import { cx } from './tones'

export type MeterLevel = 'ok' | 'warn' | 'danger'

export function meterState(value: number, max: number, warnAt = 0.7, dangerAt = 0.9): { fraction: number; level: MeterLevel } {
  const fraction = max > 0 && Number.isFinite(value) ? Math.min(1, Math.max(0, value / max)) : 0
  return { fraction, level: fraction >= dangerAt ? 'danger' : fraction >= warnAt ? 'warn' : 'ok' }
}

const FILL: Record<MeterLevel, string> = { ok: 'bg-ok', warn: 'bg-warn', danger: 'bg-danger' }
const NOTE: Record<MeterLevel, string> = { ok: '', warn: 'high', danger: 'near limit' }

/** Budget or rate meter. The numbers are always printed; the "high" / "near limit" note backs up the color. */
export function Meter({ label, value, max, valueText, warnAt, dangerAt, className }: {
  label: string
  value: number
  max: number
  valueText?: string
  warnAt?: number
  dangerAt?: number
  className?: string
}) {
  const { fraction, level } = meterState(value, max, warnAt, dangerAt)
  const text = valueText ?? `${value} / ${max}`
  return (
    <div className={className}>
      <div className="flex justify-between gap-2 text-xs text-muted">
        <span>{label}</span>
        <span className="font-mono text-fg">{text}{NOTE[level] && <span className="ml-2 font-sans text-muted">({NOTE[level]})</span>}</span>
      </div>
      <div className="mt-1 h-2 overflow-hidden rounded-full bg-raised ring-1 ring-line" role="progressbar" aria-label={label}
        aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(fraction * 100)} aria-valuetext={text}>
        <div className={cx('h-full rounded-full', FILL[level])} style={{ width: `${fraction * 100}%` }} />
      </div>
    </div>
  )
}
