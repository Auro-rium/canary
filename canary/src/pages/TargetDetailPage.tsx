import { Link, useParams } from 'react-router-dom'
import { Card, Page, PageHeader } from '../components/Console'
import { VerificationPanel } from '../components/TargetParts'
import { ErrorState, SkeletonList, StatusBadge, primaryButtonClass } from '../components/ui'
import { getTarget } from '../lib/api'
import { formatDate } from '../lib/presentation'
import { useLoad } from '../lib/useLoad'
import { can, PERMISSION, useMe } from '../lib/useMe'

export default function TargetDetailPage() {
  const { targetId = '' } = useParams()
  const { me } = useMe()
  const { data: target, error, loading, reload, setData } = useLoad(() => getTarget(targetId), targetId)
  const canWrite = can(me, PERMISSION.targetsWrite)
  const canRun = can(me, PERMISSION.campaignsLaunch)

  return (
    <Page>
      <PageHeader eyebrow="Target" title={target?.name ?? 'Target'}>
        {target && <StatusBadge status={target.verified ? 'verified' : 'unverified'} />}
        {target?.environment === 'production' && <StatusBadge status="production" />}
        {target?.verified && canRun && <Link to={`/campaigns/new?target=${target.target_id}`} className={primaryButtonClass}>Run a campaign</Link>}
      </PageHeader>
      {error && <ErrorState title="Could not load this target" message={error} onRetry={reload} />}
      {loading && !target && !error && <SkeletonList rows={4} label="Loading target" />}
      {target && (
        <div className="max-w-3xl space-y-6">
          <Card>
            <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-[10rem_1fr]">
              <dt className="text-muted">Endpoint</dt><dd className="break-all font-mono text-xs">{target.endpoint}</dd>
              <dt className="text-muted">Environment</dt><dd>{target.environment}</dd>
              <dt className="text-muted">Auth</dt><dd>{String((target.auth as { type?: unknown }).type ?? 'none')} (secrets are never shown)</dd>
              <dt className="text-muted">Session mode</dt><dd>{target.session_mode}</dd>
              <dt className="text-muted">Response path</dt><dd className="font-mono text-xs">{target.response_path ?? '(whole body)'}</dd>
              <dt className="text-muted">Verified</dt><dd>{target.verified ? `${formatDate(target.verified_at)} via ${target.verified_method ?? 'unknown'}` : 'not yet'}</dd>
            </dl>
          </Card>
          {canWrite && !target.verified && <VerificationPanel targetId={target.target_id} instructions={null} onVerified={verified => setData(() => verified)} />}
        </div>
      )}
    </Page>
  )
}
