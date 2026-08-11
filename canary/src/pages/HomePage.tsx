import { useEffect, useState } from 'react'
import Hero from '../components/Hero'
import { ErrorNotice, Metric } from '../components/Console'
import { getOverview } from '../lib/api'
import { pageClass } from '../lib/presentation'
import type { DashboardOverview } from '../lib/types'

export default function HomePage() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { getOverview().then(setOverview).catch(error => setError(error.message)) }, [])
  return <main className={pageClass.replace('pt-24', '')}><Hero overview={overview} />
    <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-10 border-t border-white/10"><div className="flex flex-wrap gap-3 items-stretch">
      <Metric label="Backend" value={overview?.backend.status ?? 'Unavailable'} tone={error ? 'danger' : 'default'} />
      <Metric label="Active runs" value={overview?.backend.active_runs ?? '—'} tone="warning" />
      <Metric label="LLM calls" value={overview?.llm_stats.calls ?? '—'} />
      <Metric label="Total tokens" value={overview?.llm_stats.total_tokens.toLocaleString() ?? '—'} />
    </div>{error && <div className="mt-5"><ErrorNotice message={`Unable to load live backend overview: ${error}`} /></div>}</section>
  </main>
}
