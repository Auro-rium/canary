import { Page, PageHeader } from '../components/Console'
import { EmptyState, ErrorState, SkeletonList, StatusBadge, Table, buttonClass, type Column } from '../components/ui'
import { listCampaigns, reportUrl } from '../lib/api'
import { isCampaignTerminal } from '../lib/liveState'
import { formatDate } from '../lib/presentation'
import { useLoad } from '../lib/useLoad'
import type { CampaignSummary } from '../lib/v2'
import { useSearchParams } from 'react-router-dom'

const PAGE_SIZE = 25
const FORMATS = [{ id: 'json', label: 'JSON' }, { id: 'md', label: 'Markdown' }, { id: 'pdf', label: 'PDF' }] as const

const columns: Column<CampaignSummary>[] = [
  { key: 'target', header: 'Campaign', sortValue: c => (c.target_name ?? c.target_id).toLowerCase(), cell: c => <span className="font-medium">{c.target_name ?? c.target_id}</span> },
  { key: 'status', header: 'Status', sortValue: c => c.status, cell: c => <StatusBadge status={c.status} /> },
  { key: 'created', header: 'Started', sortValue: c => c.created_at, cell: c => <span className="whitespace-nowrap text-muted">{formatDate(c.created_at)}</span> },
  {
    key: 'downloads', header: 'Download',
    cell: c => isCampaignTerminal(c.status)
      ? <span className="flex flex-wrap gap-2">{FORMATS.map(f => <a key={f.id} href={reportUrl(c.campaign_id, f.id)} className={buttonClass} aria-label={`Download ${f.label} report for ${c.target_name ?? c.target_id}`}>{f.label}</a>)}</span>
      : <span className="text-xs text-muted">Available when the campaign finishes</span>,
  },
]

/** Report downloads (JSON, Markdown, PDF) from GET /api/v2/reports/{id}; the files are served by the API, never rendered here. */
export default function ReportsPage() {
  const [search, setSearch] = useSearchParams()
  const page = Number(search.get('page') ?? '1') || 1
  const { data, error, loading, reload } = useLoad(() => listCampaigns(new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) })), `p${page}`)
  return (
    <Page>
      <PageHeader title="Reports" description="Download the evidence for a finished campaign. Reports are redacted exactly like the transcripts." />
      {error && <ErrorState title="Could not load campaigns" message={error} onRetry={reload} />}
      {loading && !data && !error && <SkeletonList rows={4} label="Loading reports" />}
      {data && data.items.length === 0 && <EmptyState title="No reports yet" description="Reports appear here once a campaign has run." />}
      {data && data.items.length > 0 && (
        <Table caption="Campaign reports" columns={columns} rows={data.items} rowKey={c => c.campaign_id}
          paging={{ page, pageSize: data.page_size, total: data.total, onPageChange: next => setSearch({ page: String(next) }) }} testId="reports-table" />
      )}
    </Page>
  )
}
