import type { AuthSession } from '../lib/auth'

interface AuthGateProps {
  session: AuthSession | null
  loading: boolean
  error?: string
  onLogin: () => void
}

export default function AuthGate({ session, loading, error, onLogin }: AuthGateProps) {
  if (loading) {
    return <main className="flex min-h-screen items-center justify-center bg-black font-mono text-sm text-white/60">Checking GitHub session…</main>
  }
  if (error) {
    return <main className="flex min-h-screen items-center justify-center bg-black px-6 font-mono text-sm text-red-200"><p className="border border-red-500/40 bg-red-500/10 p-5">{error}</p></main>
  }
  if (session?.authenticated) return null
  return (
    <main className="flex min-h-screen items-center justify-center bg-black px-6 font-mono text-white">
      <section className="w-full max-w-md border border-white/15 bg-white/[0.03] p-8">
        <p className="text-[10px] uppercase tracking-[0.24em] text-red-400">Agent Canary</p>
        <h1 className="mt-4 text-3xl font-semibold tracking-tight">CI for AI-agent security.</h1>
        <p className="mt-4 text-sm leading-6 text-white/55">Sign in with GitHub to inspect projects, accepted baselines, release gates, and adversarial evidence.</p>
        <button onClick={onLogin} className="mt-8 flex w-full items-center justify-center gap-3 bg-white px-5 py-3 text-xs font-medium uppercase tracking-[0.16em] text-black transition hover:bg-white/80">
          <svg aria-hidden="true" viewBox="0 0 24 24" className="h-4 w-4 fill-current"><path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2.16c-3.22.7-3.9-1.37-3.9-1.37-.53-1.35-1.29-1.71-1.29-1.71-1.05-.72.08-.71.08-.71 1.16.08 1.77 1.2 1.77 1.2 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.25.73-1.54-2.57-.29-5.27-1.28-5.27-5.72 0-1.26.45-2.29 1.2-3.1-.12-.3-.52-1.47.11-3.06 0 0 .98-.31 3.17 1.18a10.93 10.93 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.06.75.81.4 1.25.73 1.54-2.57-.29-5.27-1.28-5.27-5.72 0-1.26.45-2.29 1.2-3.1-.12-.3-.52-1.47.11-3.06 0 0 .98-.31 3.17 1.18a10.93 10.93 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.06.75.81 1.2 1.84 1.2 3.1 0 4.45-2.7 5.42-5.28 5.71.41.36.78 1.07.78 2.16v3.2c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" /></svg>
          Sign in with GitHub
        </button>
      </section>
    </main>
  )
}
