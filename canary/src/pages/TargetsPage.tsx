import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { EmptyState, ErrorNotice, PageHeader, StatusBadge } from '../components/Console'
import { hasRole, useMe } from '../lib/useMe'
import { listTargets } from '../lib/api'
import { gutter, pageClass } from '../lib/presentation'
import type { TargetView } from '../lib/v2'

export default function TargetsPage() {
  const { me } = useMe()
  const [targets, setTargets] = useState<TargetView[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { listTargets().then(result => setTargets(result.items)).catch(e => setError((e as Error).message)) }, [])

  return (
    <main className={pageClass}>
      <PageHeader eyebrow="Authorized targets" title="Targets">
        {hasRole(me?.role, 'operator', 'admin') && <Link to="/targets/new" className="px-4 py-2 bg-red-600 text-xs uppercase tracking-wider hover:bg-red-500">Add target</Link>}
      </PageHeader>
      <section className={`${gutter} py-8`}>
        {error && <ErrorNotice message={error} />}
        {!targets && !error && <EmptyState>Loading targets</EmptyState>}
        {targets?.length === 0 && <EmptyState>No targets registered</EmptyState>}
        {targets && targets.length > 0 && (
          <ul className="grid md:grid-cols-2 gap-3">
            {targets.map(target => (
              <li key={target.target_id} className="border border-white/10 p-4">
                <Link to={`/targets/${target.target_id}`} className="text-sm hover:underline">{target.name}</Link>
                <p className="mt-1 text-[10px] text-white/40 break-all">{target.endpoint}</p>
                <div className="mt-3 flex gap-2"><StatusBadge status={target.verified ? 'verified' : 'unverified'} />{target.environment === 'production' && <StatusBadge status="production" />}</div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  )
}
