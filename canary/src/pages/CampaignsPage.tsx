import { useCallback, useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { EmptyState, ErrorNotice, Metric, PageHeader, StatusBadge } from '../components/Console'
import { getRuns, getTargets } from '../lib/api'
import { formatDate, pageClass } from '../lib/presentation'
import type { PaginatedRuns, TargetsResponse } from '../lib/types'

const PAGE_SIZE = 25

export default function CampaignsPage() {
  const [search, setSearch] = useSearchParams()
  const [data, setData] = useState<PaginatedRuns | null>(null)
  const [targets, setTargets] = useState<TargetsResponse>({ items: [] })
  const [error, setError] = useState<string | null>(null)
  const page = Number(search.get('page') ?? '1') || 1
  const target = search.get('target') ?? ''
  const status = search.get('status') ?? ''
  const load = useCallback(() => {
    const query = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) })
    if (target) query.set('target_id', target)
    if (status) query.set('status', status)
    setError(null)
    Promise.all([getRuns(query), getTargets()]).then(([runs, targetList]) => { setData(runs); setTargets(targetList) }).catch(error => setError(error.message))
  }, [page, status, target])
  useEffect(load, [load])
  const change = (key: string, value: string) => { const next = new URLSearchParams(search); if (value) next.set(key, value); else next.delete(key); next.set('page', '1'); setSearch(next) }
  const setPage = (nextPage: number) => { const next = new URLSearchParams(search); next.set('page', String(nextPage)); setSearch(next) }
  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1
  return <main className={pageClass}><PageHeader eyebrow="Campaign operations" title="All campaigns"><Link to="/campaigns/new" className="px-4 py-2 bg-red-600 text-xs uppercase tracking-wider hover:bg-red-500">Run audit</Link></PageHeader>
    <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-6 border-b border-white/10 flex flex-wrap gap-3"><Metric label="Campaigns" value={data?.total ?? '—'} /><Metric label="Page" value={`${page} / ${totalPages}`} /><Metric label="Selected target" value={target ? '1' : 'All'} /></section>
    <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-6 border-b border-white/10 flex flex-wrap gap-3"><label className="text-[10px] text-white/45 uppercase tracking-wider">Target <select value={target} onChange={event => change('target', event.target.value)} className="ml-2 bg-black border border-white/20 px-2 py-1 text-white"><option value="">All targets</option>{targets.items.map(item => <option key={item.target_id} value={item.target_id}>{item.target_id}</option>)}</select></label><label className="text-[10px] text-white/45 uppercase tracking-wider">Status <select value={status} onChange={event => change('status', event.target.value)} className="ml-2 bg-black border border-white/20 px-2 py-1 text-white"><option value="">All</option><option value="running">Running</option><option value="completed">Completed</option><option value="failed">Failed</option></select></label></section>
    <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-8">{error && <ErrorNotice message={error} />}{!data && !error && <EmptyState>Loading campaign history</EmptyState>}{data?.items.length === 0 && <EmptyState>No campaigns match these filters</EmptyState>}{data && data.items.length > 0 && <div className="overflow-x-auto border border-white/10"><table className="w-full min-w-[900px] text-left"><thead className="bg-white/[0.03] text-[9px] uppercase tracking-[0.15em] text-white/35"><tr>{['Campaign', 'Target', 'Status', 'Started', 'Attacks', 'Findings', 'LLM tokens'].map(item => <th key={item} className="px-4 py-3 font-normal">{item}</th>)}</tr></thead><tbody>{data.items.map(run => <tr key={run.run_id} className="border-t border-white/[0.06] hover:bg-white/[0.025]"><td className="px-4 py-3"><Link className="text-white hover:text-red-400" to={`/campaigns/${run.run_id}`}>{run.run_id}</Link></td><td className="px-4 py-3 text-xs text-white/55 max-w-[280px] truncate">{run.target_id}</td><td className="px-4 py-3"><StatusBadge status={run.status} /></td><td className="px-4 py-3 text-[10px] text-white/45">{formatDate(run.start_time)}</td><td className="px-4 py-3 text-xs text-white/65">{run.total_attacks}</td><td className="px-4 py-3 text-xs text-red-400">{run.successful_attacks}</td><td className="px-4 py-3 text-xs text-white/65">{run.llm_stats.total_tokens.toLocaleString()}</td></tr>)}</tbody></table></div>}
      {data && <div className="mt-5 flex items-center justify-between text-xs"><button disabled={page <= 1} onClick={() => setPage(page - 1)} className="border border-white/20 px-3 py-2 disabled:opacity-30">Previous</button><span className="text-white/40">{data.total} campaigns</span><button disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="border border-white/20 px-3 py-2 disabled:opacity-30">Next</button></div>}</section>
  </main>
}
