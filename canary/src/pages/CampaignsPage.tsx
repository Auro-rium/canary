import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { EmptyState, ErrorNotice, Metric, PageHeader, StatusBadge } from '../components/Console'
import { hasRole, useMe } from '../lib/useMe'
import { listCampaigns } from '../lib/api'
import { formatDate, gutter, pageClass } from '../lib/presentation'
import type { CampaignSummary, Paged } from '../lib/v2'

const PAGE_SIZE = 25

export default function CampaignsPage() {
  const [search, setSearch] = useSearchParams()
  const { me } = useMe()
  const [data, setData] = useState<Paged<CampaignSummary> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const page = Number(search.get('page') ?? '1') || 1

  useEffect(() => {
    const query = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) })
    let live = true
    listCampaigns(query)
      .then(result => { if (live) { setData(result); setError(null) } })
      .catch(e => { if (live) setError((e as Error).message) })
    return () => { live = false }
  }, [page])

  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1
  const goto = (next: number) => { const params = new URLSearchParams(search); params.set('page', String(next)); setSearch(params) }

  return (
    <main className={pageClass}>
      <PageHeader eyebrow="Campaign operations" title="Campaigns">
        {hasRole(me?.role, 'operator', 'admin') && <Link to="/campaigns/new" className="px-4 py-2 bg-red-600 text-xs uppercase tracking-wider hover:bg-red-500">New campaign</Link>}
      </PageHeader>
      <section className={`${gutter} py-6 border-b border-white/10 flex flex-wrap gap-3`}>
        <Metric label="Campaigns" value={data?.total ?? '—'} />
        <Metric label="Page" value={`${page} / ${totalPages}`} />
      </section>
      <section className={`${gutter} py-8`}>
        {error && <ErrorNotice message={error} />}
        {!data && !error && <EmptyState>Loading campaigns</EmptyState>}
        {data?.items.length === 0 && <EmptyState>No campaigns yet</EmptyState>}
        {data && data.items.length > 0 && (
          <table className="w-full text-xs">
            <thead><tr className="text-left text-[9px] uppercase tracking-wider text-white/30"><th className="py-2 font-normal">Target</th><th className="font-normal">Status</th><th className="font-normal">Confirmed</th><th className="font-normal">Started</th></tr></thead>
            <tbody>
              {data.items.map(campaign => (
                <tr key={campaign.campaign_id} className="border-t border-white/10">
                  <td className="py-3"><Link className="hover:underline" to={`/campaigns/${campaign.campaign_id}`}>{campaign.target_name ?? campaign.target_id}</Link></td>
                  <td><StatusBadge status={campaign.status} /> {campaign.environment === 'production' && <StatusBadge status="production" />}</td>
                  <td>{campaign.confirmed} / {campaign.total_conversations}</td>
                  <td className="text-white/50">{formatDate(campaign.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {data && (
          <div className="mt-5 flex items-center justify-between text-xs">
            <button disabled={page <= 1} onClick={() => goto(page - 1)} className="border border-white/20 px-3 py-2 disabled:opacity-30">Previous</button>
            <span className="text-white/40">{data.total} total</span>
            <button disabled={page >= totalPages} onClick={() => goto(page + 1)} className="border border-white/20 px-3 py-2 disabled:opacity-30">Next</button>
          </div>
        )}
      </section>
    </main>
  )
}
