import { useEffect, useState } from 'react'
import { Card } from '../components/Console'
import { ErrorState, SkeletonList, primaryButtonClass } from '../components/ui'
import { listProviders, loginUrl } from '../lib/api'

/** Shown instead of the app when /api/v2/me answers 401. Sign-in is a full-page OIDC redirect. */
export default function LoginPage() {
  const [providers, setProviders] = useState<string[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { listProviders().then(r => setProviders(r.providers)).catch(e => setError((e as Error).message)) }, [])
  const next = `${window.location.pathname}${window.location.search}`

  return (
    <div className="mx-auto max-w-md px-gutter py-12">
      <Card className="space-y-4 p-6 shadow-e2">
        <p className="text-xs font-semibold uppercase tracking-wide text-muted">Authorized operators only</p>
        <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
        <p className="text-muted">Canary runs adversarial conversations only against agents your organisation owns and has verified. Sign in with your organisation account.</p>
        {error && <ErrorState title="Cannot load sign-in options" message={error} />}
        {!providers && !error && <SkeletonList rows={1} label="Loading sign-in options" />}
        {providers?.length === 0 && <ErrorState title="Sign-in unavailable" message="No sign-in provider is configured on this server." />}
        <ul className="space-y-3">
          {providers?.map(provider => (
            <li key={provider}><a data-testid={`login-${provider}`} href={loginUrl(provider, next)} className={`${primaryButtonClass} w-full`}>Continue with {provider}</a></li>
          ))}
        </ul>
      </Card>
    </div>
  )
}
