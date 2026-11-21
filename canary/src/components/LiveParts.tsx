import type { LiveCell } from '../lib/liveState'
import { statusStyle, strategyLabel, VERDICT_STYLE } from '../lib/presentation'
import type { BudgetState } from '../lib/v2'
import { Meter, TONE_CLASSES, cx } from './ui'

export type Connection = 'connected' | 'reconnecting' | 'idle'

/** SSE connection indicator: glyph + words, never color alone. */
export function ConnectionIndicator({ connection, finished }: { connection: Connection; finished: boolean }) {
  const view = finished
    ? { tone: 'neutral', icon: '■', text: 'Finished', detail: 'The campaign has ended; the stream is closed.' }
    : connection === 'connected' ? { tone: 'ok', icon: '●', text: 'Live', detail: 'Receiving events.' }
    : connection === 'reconnecting' ? { tone: 'warn', icon: '↻', text: 'Reconnecting', detail: 'Connection lost; resuming from the last event.' }
    : { tone: 'neutral', icon: '○', text: 'Connecting', detail: 'Opening the event stream.' }
  return (
    <span data-testid="sse-status" data-state={finished ? 'finished' : connection} title={view.detail}
      className={cx('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium', TONE_CLASSES[view.tone as 'ok'])}>
      <span aria-hidden="true">{view.icon}</span>Stream: {view.text}
    </span>
  )
}

export function BudgetMeter({ budget }: { budget: BudgetState | null }) {
  if (!budget) return <p data-testid="budget-meter" className="text-xs text-muted">Budget: waiting for the first update</p>
  return (
    <div data-testid="budget-meter" className="grid gap-4 sm:grid-cols-2">
      <Meter label="Requests" value={budget.requests_used} max={budget.max_total_requests} valueText={`${budget.requests_used} / ${budget.max_total_requests}`} />
      <Meter label="LLM cost" value={budget.llm_cost_usd} max={budget.max_llm_cost_usd} valueText={`$${budget.llm_cost_usd.toFixed(2)} / $${budget.max_llm_cost_usd.toFixed(2)}`} />
    </div>
  )
}

/** Technique (rows) by trial (columns). Cells wrap on narrow screens, so the page never scrolls sideways. */
export function ConversationGrid({
  cells, techniques, trials, selected, onSelect,
}: {
  cells: LiveCell[]
  techniques: string[]
  trials: number
  selected: string | null
  onSelect: (conversationId: string) => void
}) {
  const byKey = new Map(cells.map(cell => [`${cell.technique}:${cell.trial_index}`, cell]))
  const columns = Math.max(trials, ...cells.map(cell => cell.trial_index + 1), 1)
  return (
    <div className="space-y-4" data-testid="conversation-grid" role="group" aria-label="Conversations by technique and trial">
      {techniques.map(technique => (
        <section key={technique} aria-label={strategyLabel(technique)}>
          <h3 className="mb-1.5 font-semibold">{strategyLabel(technique)}</h3>
          <ul className="grid gap-2 [grid-template-columns:repeat(auto-fill,minmax(8.25rem,1fr))]">
            {Array.from({ length: columns }, (_, trial) => {
              const cell = byKey.get(`${technique}:${trial}`)
              if (!cell) {
                return <li key={trial}><div className="flex h-[4.5rem] flex-col justify-center rounded-md border border-dashed border-line-strong px-2 text-xs text-muted"><span className="font-semibold">Trial {trial + 1}</span><span>pending</span></div></li>
              }
              const style = statusStyle(cell.status)
              const verdict = cell.verdict ? (VERDICT_STYLE as Record<string, { tone: string; icon: string }>)[cell.verdict] ?? null : null
              const isSelected = selected === cell.conversation_id
              return (
                <li key={trial}>
                  <button type="button" data-testid={`cell-${technique}-${trial}`} data-status={cell.status} onClick={() => onSelect(cell.conversation_id)} aria-pressed={isSelected}
                    className={cx('flex h-[4.5rem] w-full flex-col justify-center rounded-md border px-2 text-left text-xs leading-snug', TONE_CLASSES[style.tone], cell.status === 'running' && 'animate-pulse-soft', isSelected && 'outline outline-2 outline-offset-2 outline-fg')}>
                    <span className="font-semibold">Trial {trial + 1}</span>
                    <span><span aria-hidden="true">{style.icon} </span>{style.label}</span>
                    <span>{cell.turns} turns{cell.hits.length > 0 ? ` · ${cell.hits.length} hit${cell.hits.length > 1 ? 's' : ''}` : ''}{verdict && cell.verdict ? <> · <span className="font-semibold"><span aria-hidden="true">{verdict.icon} </span>{cell.verdict}</span></> : null}</span>
                  </button>
                </li>
              )
            })}
          </ul>
        </section>
      ))}
    </div>
  )
}
