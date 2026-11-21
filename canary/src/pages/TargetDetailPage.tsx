import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ErrorNotice, PageHeader, primaryButtonClass, StatusBadge } from '../components/Console'
import { can, PERMISSION, useMe } from '../lib/useMe'
import { VerificationPanel } from '../components/TargetParts'
import { getTarget } from '../lib/api'
import { gutter, pageClass } from '../lib/presentation'
import type { TargetView } from '../lib/v2'

export default function TargetDetailPage() {
  const { targetId = '' } = useParams()
  const { me } = useMe()
  const [target, setTarget] = useState<TargetView | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { getTarget(targetId).then(setTarget).catch(e => setError((e as Error).message)) }, [targetId])
  const canRun = can(me, PERMISSION.targetsWrite)

  return (
    <main className={pageClass}>
      <PageHeader eyebrow="Target" title={target?.name ?? 'Target'}>
        {target && <StatusBadge status={target.verified ? 'verified' : 'unverified'} />}
        {target?.environment === 'production' && <StatusBadge status="production" />}
        {target?.verified && canRun && <Link to={`/campaigns/new?target=${target.target_id}`} className={primaryButtonClass}>Run a campaign</Link>}
      </PageHeader>
      <section className={`${gutter} py-8 max-w-3xl space-y-8`}>
        {error && <ErrorNotice message={error} />}
        {target && (
          <>
            <dl className="grid grid-cols-[10rem_1fr] gap-y-1 text-xs">
              <dt className="text-white/60">Endpoint</dt><dd className="break-all">{target.endpoint}</dd>
              <dt className="text-white/60">Auth</dt><dd>{String((target.auth as { type?: unknown }).type ?? 'none')} (secrets are never shown)</dd>
              <dt className="text-white/60">Session mode</dt><dd>{target.session_mode}</dd>
              <dt className="text-white/60">Response path</dt><dd>{target.response_path ?? '(whole body)'}</dd>
            </dl>
            {canRun && !target.verified && <VerificationPanel targetId={target.target_id} instructions={null} onVerified={setTarget} />}
          </>
        )}
      </section>
    </main>
  )
}
