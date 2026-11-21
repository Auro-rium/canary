import type { TechniqueResult } from '../lib/contracts'
import { budgetFraction, type LiveCell } from '../lib/liveState'
import { CONVERSATION_STATUS_STYLE, percent, strategyLabel, VERDICT_STYLE } from '../lib/presentation'
import type { BudgetState } from '../lib/v2'

export function BudgetMeter({ budget }: { budget: BudgetState | null }) {
  if (!budget) return <p className="text-[10px] text-white/60 uppercase tracking-wider">Budget: waiting for first update</p>
  const rows = [
    { label: 'Requests', used: budget.requests_used, max: budget.max_total_requests, text: `${budget.requests_used} / ${budget.max_total_requests}` },
    { label: 'LLM cost', used: budget.llm_cost_usd, max: budget.max_llm_cost_usd, text: `$${budget.llm_cost_usd.toFixed(2)} / $${budget.max_llm_cost_usd.toFixed(2)}` },
  ]
  return (
    <div data-testid="budget-meter" className="grid sm:grid-cols-2 gap-4">
      {rows.map(row => {
        const fraction = budgetFraction(row.used, row.max)
        return (
          <div key={row.label}>
            <div className="flex justify-between text-[10px] uppercase tracking-wider text-white/50">
              <span>{row.label}</span><span>{row.text}</span>
            </div>
            <div className="mt-1 h-2 bg-white/10" role="progressbar" aria-label={row.label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(fraction * 100)}>
              <div className={`h-full ${fraction > 0.9 ? 'bg-red-500' : fraction > 0.7 ? 'bg-orange-400' : 'bg-emerald-400'}`} style={{ width: `${fraction * 100}%` }} />
            </div>
          </div>
        )
      })}
    </div>
  )
}

/** Technique (rows) x trial (columns); one button per conversation. */
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
    <div className="overflow-x-auto">
      <table className="text-[10px] border-separate border-spacing-1" data-testid="conversation-grid">
        <thead>
          <tr>
            <th className="text-left text-white/60 uppercase tracking-wider font-normal pr-3">Technique</th>
            {Array.from({ length: columns }, (_, trial) => <th key={trial} className="text-white/60 font-normal">T{trial + 1}</th>)}
          </tr>
        </thead>
        <tbody>
          {techniques.map(technique => (
            <tr key={technique}>
              <th scope="row" className="text-left text-white/60 font-normal pr-3 whitespace-nowrap">{strategyLabel(technique)}</th>
              {Array.from({ length: columns }, (_, trial) => {
                const cell = byKey.get(`${technique}:${trial}`)
                if (!cell) return <td key={trial}><div className="w-24 h-12 border border-dashed border-white/10 text-white/60 flex items-center justify-center">pending</div></td>
                const style = (CONVERSATION_STATUS_STYLE as Record<string, { label: string; classes: string }>)[cell.status] ?? { label: cell.status, classes: CONVERSATION_STATUS_STYLE.error.classes }
                return (
                  <td key={trial}>
                    <button
                      type="button"
                      data-testid={`cell-${technique}-${trial}`}
                      data-status={cell.status}
                      onClick={() => onSelect(cell.conversation_id)}
                      aria-pressed={selected === cell.conversation_id}
                      className={`w-24 h-12 border px-1 text-left leading-tight ${style.classes} ${selected === cell.conversation_id ? 'ring-2 ring-white' : ''}`}
                    >
                      <span className="block">{style.label}</span>
                      <span className="block text-white/50">{cell.turns} turns{cell.hits.length > 0 ? ` · ${cell.hits.length} hit` : ''}</span>
                      {cell.verdict && <span className={`block ${(VERDICT_STYLE as Record<string, string>)[cell.verdict] ?? ''}`}>{cell.verdict}</span>}
                    </button>
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Wilson-interval bar: filled marker at the rate, band from ci95_low to ci95_high. */
export function CiBar({ result }: { result: TechniqueResult }) {
  const pct = (value: number) => `${Math.min(100, Math.max(0, value * 100))}%`
  return (
    <div className="relative h-3 w-48 bg-white/10" role="img" aria-label={`${percent(result.success_rate)} (95% CI ${percent(result.ci95_low)} to ${percent(result.ci95_high)})`}>
      <div className="absolute inset-y-0 bg-red-500/40" style={{ left: pct(result.ci95_low), width: `${Math.max(0, (result.ci95_high - result.ci95_low) * 100)}%` }} />
      <div className="absolute inset-y-[-2px] w-[3px] bg-red-400" style={{ left: pct(result.success_rate) }} />
    </div>
  )
}

export function ResultsTable({ results }: { results: TechniqueResult[] }) {
  if (results.length === 0) return <p className="text-xs text-white/60">Results appear when the campaign completes.</p>
  return (
    <table className="w-full text-xs" data-testid="results-table">
      <thead>
        <tr className="text-left text-[9px] uppercase tracking-wider text-white/60">
          <th className="py-2 font-normal">Technique</th><th className="font-normal">Confirmed / trials</th>
          <th className="font-normal">Success rate</th><th className="font-normal">95% CI</th><th className="font-normal">Interval</th>
        </tr>
      </thead>
      <tbody>
        {results.map(result => (
          <tr key={result.technique} className="border-t border-white/10">
            <td className="py-2">{strategyLabel(result.technique)}</td>
            <td>{result.confirmed} / {result.trials}</td>
            <td>{percent(result.success_rate)}</td>
            <td className="text-white/50">{percent(result.ci95_low)} – {percent(result.ci95_high)}</td>
            <td><CiBar result={result} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
