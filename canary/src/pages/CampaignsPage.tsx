import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Metric, Page, PageHeader } from '../components/Console'
import { EmptyState, ErrorState, SkeletonList, StatusBadge, Table, primaryButtonClass, type Column, type SortState } from '../components/ui'
import { listCampaigns } from '../lib/api'
import { formatDate } from '../lib/presentation'
import { can, PERMISSION, useMe } from '../lib/useMe'
import { useLoad } from '../lib/useLoad'
import type { CampaignSummary } from '../lib/v2'

const PAGE_SIZE = 25

const columns: Column<CampaignSummary>[] = [
  { key: 'target', header: 'Target', sortValue: c => (c.target_name ?? c.target_id).toLowerCase(), cell: c => <Link className="font-medium hover:underline" to={`/campaigns/${c.campaign_id}`}>{c.target_name ?? c.target_id}</Link> },
  { key: 'status', header: 'Status', sortValue: c => c.status, cell: c => <span className="flex flex-wrap gap-1"><StatusBadge status={c.status} />{c.environment === 'production' && <StatusBadge status="production" />}</span> },
  { key: 'confirmed', header: 'Confirmed / conversations', sortValue: c => c.confirmed, cell: c => <span className="font-mono">{c.confirmed} / {c.total_conversations}</span> },
  { key: 'created', header: 'Started', sortValue: c => c.created_at, cell: c => <span className="whitespace-nowrap text-muted">{formatDate(c.created_at)}</span> },
  { key: 'results', header: 'Results', cell: c => <Link className="text-xs underline" to={`/campaigns/${c.campaign_id}/results`} aria-label={`Results for ${c.target_name ?? c.target_id}`}>Results</Link> },
]

export default function CampaignsPage() {
  const [search, setSearch] = useSearchParams()
  const { me } = useMe()
  const page = Number(search.get('page') ?? '1') || 1
  const { data, error, loading, reload } = useLoad(() => listCampaigns(new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) })), `p${page}`)
  const [sort, setSort] = useState<SortState | null>(null)
  const goto = (next: number) => { const params = new URLSearchParams(search); params.set('page', String(next)); setSearch(params) }
  const launch = <Link to="/campaigns/new" className={primaryButtonClass}>New campaign</Link>
  const canLaunch = can(me, PERMISSION.campaignsLaunch)

  return (
    <Page>
      <PageHeader title="Campaigns" description="Adversarial multi-turn runs against your verified targets.">{canLaunch && launch}</PageHeader>
      {error && <ErrorState title="Could not load campaigns" message={error} onRetry={reload} />}
      {loading && !data && !error && <SkeletonList rows={5} label="Loading campaigns" />}
      {data && data.items.length === 0 && <EmptyState title="No campaigns yet" description="Launch a campaign against a verified target to see live results here." action={canLaunch ? launch : undefined} />}
      {data && data.items.length > 0 && (
        <>
          <div className="mb-4 flex flex-wrap gap-3"><Metric label="Campaigns" value={data.total} /></div>
          <Table caption="Campaigns" columns={columns} rows={data.items} rowKey={c => c.campaign_id} sort={sort} onSortChange={setSort} paging={{ page, pageSize: data.page_size, total: data.total, onPageChange: goto }} testId="campaigns-table" />
        </>
      )}
    </Page>
  )
}
