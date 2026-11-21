import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Metric, Page, PageHeader } from '../components/layout'
import { Badge, EmptyState, ErrorState, SkeletonList, StatusBadge, Table, primaryButtonClass, type Column, type SortState } from '../components/ui'
import { listTargets } from '../lib/api'
import { formatDate } from '../lib/presentation'
import { can, PERMISSION, useMe } from '../lib/useMe'
import { useLoad } from '../lib/useLoad'
import type { TargetView } from '../lib/v2'

const columns: Column<TargetView>[] = [
  { key: 'name', header: 'Name', sortValue: t => t.name.toLowerCase(), cell: t => <Link to={`/targets/${t.target_id}`} className="font-medium underline-offset-2 hover:underline">{t.name}</Link> },
  { key: 'endpoint', header: 'Endpoint', cell: t => <span className="break-all font-mono text-xs text-muted">{t.endpoint}</span>, className: 'min-w-[12rem]' },
  { key: 'environment', header: 'Environment', sortValue: t => t.environment, cell: t => t.environment === 'production' ? <StatusBadge status="production" /> : <Badge icon="○">staging</Badge> },
  { key: 'verified', header: 'Verification', sortValue: t => (t.verified ? 1 : 0), cell: t => <StatusBadge status={t.verified ? 'verified' : 'unverified'} /> },
  { key: 'created', header: 'Registered', sortValue: t => t.created_at, cell: t => <span className="whitespace-nowrap text-muted">{formatDate(t.created_at)}</span> },
]

export default function TargetsPage() {
  const { me } = useMe()
  const canAdd = can(me, PERMISSION.targetsWrite)
  const { data, error, loading, reload } = useLoad(() => listTargets().then(r => r.items), 'targets')
  const [sort, setSort] = useState<SortState | null>({ key: 'name', dir: 'asc' })
  const add = <Link to="/targets/new" className={primaryButtonClass}>Add target</Link>

  return (
    <Page>
      <PageHeader title="Targets" description="Agents Canary may test. A target must pass ownership verification before any campaign can run against it.">{canAdd && add}</PageHeader>
      {error && <ErrorState title="Could not load targets" message={error} onRetry={reload} />}
      {loading && !data && !error && <SkeletonList rows={4} label="Loading targets" />}
      {data && data.length === 0 && <EmptyState title="No targets registered yet" description="Register the first agent you own, then verify ownership to unlock campaigns." action={canAdd ? add : undefined} />}
      {data && data.length > 0 && (
        <>
          <div className="mb-4 flex flex-wrap gap-3">
            <Metric label="Targets" value={data.length} />
            <Metric label="Verified" value={`${data.filter(t => t.verified).length} / ${data.length}`} />
          </div>
          <Table caption="Targets" columns={columns} rows={data} rowKey={t => t.target_id} sort={sort} onSortChange={setSort} testId="targets-table" />
        </>
      )}
    </Page>
  )
}
