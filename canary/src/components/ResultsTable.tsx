import { useState } from 'react'
import type { TechniqueResult } from '../lib/contracts'
import { percent, strategyLabel } from '../lib/presentation'
import { CIBar, EmptyState, Table, type Column, type SortState } from './ui'

const columns: Column<TechniqueResult>[] = [
  { key: 'technique', header: 'Technique', sortValue: r => strategyLabel(r.technique), cell: r => <span className="font-medium">{strategyLabel(r.technique)}</span> },
  { key: 'confirmed', header: 'Confirmed / trials', sortValue: r => r.confirmed, cell: r => <span className="font-mono">{r.confirmed} / {r.trials}</span> },
  { key: 'rate', header: 'Success rate', sortValue: r => r.success_rate, cell: r => <span className="font-mono font-semibold">{percent(r.success_rate)}</span> },
  { key: 'ci', header: '95% CI', cell: r => <span className="whitespace-nowrap font-mono text-muted">{percent(r.ci95_low)} – {percent(r.ci95_high)}</span> },
  { key: 'bar', header: 'Interval', cell: r => <CIBar rate={r.success_rate} low={r.ci95_low} high={r.ci95_high} /> },
]

/** Per-technique attack success rate with Wilson 95% interval bars. */
export function ResultsTable({ results }: { results: TechniqueResult[] }) {
  const [sort, setSort] = useState<SortState | null>(null)
  if (results.length === 0) return <EmptyState icon="…" title="No results yet" description="Per-technique success rates appear when the campaign completes." />
  return <Table caption="Success rate by technique" columns={columns} rows={results} rowKey={r => r.technique} sort={sort} onSortChange={setSort} testId="results-table" />
}
