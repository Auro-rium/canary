import { cx } from './ui'

/** Horizontal wizard progress. Done steps get a check mark and the current one aria-current="step". */
export function Stepper({ steps, current }: { steps: readonly string[]; current: number }) {
  return (
    <ol aria-label="Wizard steps" className="flex flex-wrap gap-x-1 gap-y-2 text-xs">
      {steps.map((label, index) => {
        const done = index < current
        const active = index === current
        return (
          <li key={label} aria-current={active ? 'step' : undefined}
            className={cx('flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-medium', active ? 'border-fg bg-fg text-bg' : done ? 'border-ok/50 bg-ok-soft text-ok' : 'border-line-strong text-muted')}>
            <span aria-hidden="true">{done ? '✓' : index + 1}</span>
            <span>{label}</span>
            <span className="sr-only">{done ? ' (done)' : active ? ' (current step)' : ' (upcoming)'}</span>
          </li>
        )
      })}
    </ol>
  )
}
