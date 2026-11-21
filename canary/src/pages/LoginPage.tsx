import { useEffect, useState } from 'react'
import { ErrorNotice, PageHeader } from '../components/Console'
import { listProviders, loginUrl } from '../lib/api'
import { gutter, pageClass } from '../lib/presentation'

/** Shown instead of the app when /api/v2/me answers 401. Sign-in is a full-page OIDC redirect. */
export default function LoginPage() {
  const [providers, setProviders] = useState<string[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => { listProviders().then(r => setProviders(r.providers)).catch(e => setError((e as Error).message)) }, [])
  const next = `${window.location.pathname}${window.location.search}`

  return (
    <main className={pageClass}>
      <PageHeader eyebrow="Authorized operators only" title="Sign in" />
      <section className={`${gutter} py-8 max-w-xl space-y-4`}>
        <p className="text-xs text-white/60">Canary runs adversarial conversations only against agents your organisation owns and has verified. Sign in with your organisation account.</p>
        {error && <ErrorNotice message={error} />}
        {providers?.length === 0 && <ErrorNotice message="No sign-in provider is configured on this server." />}
        <ul className="space-y-3">
          {providers?.map(provider => (
            <li key={provider}>
              <a data-testid={`login-${provider}`} href={loginUrl(provider, next)} className="inline-block px-5 py-3 bg-red-600 text-xs uppercase tracking-wider hover:bg-red-500">Continue with {provider}</a>
            </li>
          ))}
        </ul>
      </section>
    </main>
  )
}
