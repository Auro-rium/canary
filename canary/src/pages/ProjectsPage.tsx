import { useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { ApiError, createProject, createProjectRelease, getProjectReleases, getProjects, verifyTarget } from '../lib/api'
import type { CanaryProject, CanaryRelease } from '../lib/types'

const DEFAULT_STRATEGIES = [
  'prompt_injection',
  'indirect_injection',
  'tool_misuse',
  'sensitive_data_exposure',
  'authorization_boundary',
  'retrieval_poisoning',
]

const decisionStyle = (decision: CanaryRelease['decision']) => {
  if (decision === 'block') return 'border-red-500/40 bg-red-500/10 text-red-300'
  if (decision === 'warn') return 'border-amber-400/40 bg-amber-400/10 text-amber-200'
  if (decision === 'pass') return 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200'
  return 'border-white/15 bg-white/5 text-white/50'
}

function Onboarding({ onCreated }: { onCreated: (project: CanaryProject) => void }) {
  const [name, setName] = useState('customer-support-agent')
  const [endpoint, setEndpoint] = useState('https://preview.company.ai/chat')
  const [responsePath, setResponsePath] = useState('response')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [verified, setVerified] = useState(false)
  const [verification, setVerification] = useState('')

  const verify = async () => {
    setBusy(true)
    setError('')
    setVerification('')
    try {
      const result = await verifyTarget({ endpoint, request_template: '{"message":"{{PROMPT}}"}', response_path: responsePath || undefined })
      if (result.response_path_detected === false) throw new Error('The response path was not found in the verification response')
      setVerified(true)
      setVerification(`Verified: endpoint reachable (${result.status_code})${responsePath ? ' and response path detected' : ''}.`)
    } catch (cause) {
      setVerified(false)
      setError(cause instanceof ApiError ? cause.message : cause instanceof Error ? cause.message : 'Unable to verify target')
    } finally {
      setBusy(false)
    }
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!verified) {
      setError('Verify the agent endpoint before registering this project.')
      return
    }
    setBusy(true)
    setError('')
    try {
      onCreated(await createProject({
        name,
        endpoint,
        environment: 'preview',
        request_template: '{"message":"{{PROMPT}}"}',
        response_path: responsePath || undefined,
        strategies: DEFAULT_STRATEGIES,
        gate: { block_on: ['critical', 'high'], max_new_findings: 0 },
      }))
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Unable to create project')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="mx-auto mt-16 max-w-2xl border border-white/15 bg-white/[0.03] p-8 sm:p-12">
      <p className="text-xs uppercase tracking-[0.24em] text-red-400">Create Project</p>
      <h1 className="mt-4 text-3xl font-semibold tracking-tight text-white">Connect a preview agent.</h1>
      <p className="mt-3 max-w-xl text-sm leading-6 text-white/55">Canary stores the target contract with the project, then uses its existing red-team engine to compare every release with the last completed baseline.</p>
      <form className="mt-10 space-y-5" onSubmit={submit}>
        <label className="block text-xs uppercase tracking-[0.16em] text-white/55">Project
          <input value={name} onChange={(event) => setName(event.target.value)} required className="mt-2 w-full border border-white/20 bg-black px-4 py-3 text-sm text-white outline-none focus:border-red-400" />
        </label>
        <label className="block text-xs uppercase tracking-[0.16em] text-white/55">Agent endpoint
          <input value={endpoint} onChange={(event) => { setEndpoint(event.target.value); setVerified(false) }} required type="url" className="mt-2 w-full border border-white/20 bg-black px-4 py-3 text-sm text-white outline-none focus:border-red-400" />
        </label>
        <div className="grid gap-5 sm:grid-cols-2">
          <label className="block text-xs uppercase tracking-[0.16em] text-white/55">Request format
            <code className="mt-2 block border border-white/10 bg-black px-4 py-3 text-xs text-white/70">{'{"message":"{{PROMPT}}"}'}</code>
          </label>
          <label className="block text-xs uppercase tracking-[0.16em] text-white/55">Response path
            <input value={responsePath} onChange={(event) => { setResponsePath(event.target.value); setVerified(false) }} className="mt-2 w-full border border-white/20 bg-black px-4 py-3 text-sm text-white outline-none focus:border-red-400" />
          </label>
        </div>
        {error && <p className="border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-200">{error}</p>}
        {verification && <p className="border border-emerald-400/30 bg-emerald-400/10 p-3 text-xs text-emerald-100">{verification}</p>}
        <div className="grid gap-3 sm:grid-cols-2"><button type="button" onClick={() => void verify()} disabled={busy} className="border border-white/30 px-5 py-3 text-xs font-medium uppercase tracking-[0.18em] text-white transition hover:border-white disabled:opacity-50">{busy ? 'Verifying…' : 'Verify agent'}</button><button disabled={busy || !verified} className="bg-red-600 px-5 py-3 text-xs font-medium uppercase tracking-[0.18em] text-white transition hover:bg-red-500 disabled:opacity-50">Register project</button></div>
      </form>
    </section>
  )
}

export default function ProjectsPage({ onBack }: { onBack: () => void }) {
  const [projects, setProjects] = useState<CanaryProject[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [releases, setReleases] = useState<CanaryRelease[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [commitSha, setCommitSha] = useState('')
  const [launching, setLaunching] = useState(false)

  const selected = useMemo(() => projects.find((project) => project.project_id === selectedId) ?? null, [projects, selectedId])
  const hasRunningRelease = useMemo(() => releases.some((release) => release.status === 'running'), [releases])

  useEffect(() => {
    getProjects().then((items) => {
      setProjects(items)
      setSelectedId((current) => current || items[0]?.project_id || '')
    }).catch((cause) => setError(cause instanceof ApiError ? cause.message : 'Canary API is unavailable'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!selectedId) return
    const load = () => getProjectReleases(selectedId).then(setReleases).catch((cause) => setError(cause instanceof ApiError ? cause.message : 'Unable to load releases'))
    void load()
    if (!hasRunningRelease) return
    const timer = window.setInterval(() => void load(), 5000)
    return () => window.clearInterval(timer)
  }, [selectedId, hasRunningRelease])

  const launch = async (event: FormEvent) => {
    event.preventDefault()
    if (!selected || !commitSha.trim()) return
    setLaunching(true)
    setError('')
    try {
      const release = await createProjectRelease(selected.project_id, { commit_sha: commitSha.trim(), environment: selected.environment })
      setReleases((current) => [release, ...current])
      setCommitSha('')
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Unable to start release evaluation')
    } finally {
      setLaunching(false)
    }
  }

  if (loading) return <main className="min-h-screen bg-black p-10 font-mono text-sm text-white/60">Loading projects…</main>
  if (!projects.length) return <main className="min-h-screen bg-black px-6 py-8 font-mono"><button onClick={onBack} className="text-xs uppercase tracking-[0.2em] text-white/50 hover:text-white">← Canary</button><Onboarding onCreated={(project) => { setProjects([project]); setSelectedId(project.project_id) }} /></main>

  return (
    <main className="min-h-screen bg-black px-6 py-8 font-mono text-white sm:px-10 md:px-16 lg:px-20">
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-6">
        <div><button onClick={onBack} className="text-xs uppercase tracking-[0.2em] text-white/50 hover:text-white">← Canary</button><h1 className="mt-4 text-2xl font-semibold tracking-tight">Release Security</h1></div>
        <span className="border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-[10px] uppercase tracking-[0.18em] text-emerald-200">CI gate ready</span>
      </header>
      {error && <p className="mt-6 border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-200">{error}</p>}
      <div className="mt-8 grid gap-8 lg:grid-cols-[260px_minmax(0,1fr)]">
        <aside className="border-r border-white/10 pr-6"><p className="text-[10px] uppercase tracking-[0.22em] text-white/40">Projects</p><div className="mt-4 space-y-2">{projects.map((project) => <button key={project.project_id} onClick={() => setSelectedId(project.project_id)} className={`w-full border p-4 text-left transition ${project.project_id === selectedId ? 'border-red-500/60 bg-red-500/10' : 'border-white/10 bg-white/[0.02] hover:border-white/30'}`}><strong className="block text-sm">{project.name}</strong><span className="mt-2 block text-[10px] uppercase tracking-[0.16em] text-white/45">{project.environment} · {project.slug}</span></button>)}</div></aside>
        {selected && <section>
          <div className="grid gap-5 border border-white/10 bg-white/[0.02] p-6 md:grid-cols-[1fr_auto]"><div><p className="text-[10px] uppercase tracking-[0.2em] text-white/45">Registered target</p><h2 className="mt-3 text-xl font-medium">{selected.name}</h2><p className="mt-2 break-all text-xs text-white/55">{selected.endpoint}</p><p className="mt-5 text-[10px] uppercase tracking-[0.16em] text-white/45">{selected.strategies.length} attack classes · blocks new critical and high findings</p></div><form onSubmit={launch} className="flex min-w-[240px] flex-col justify-end gap-3"><input value={commitSha} onChange={(event) => setCommitSha(event.target.value)} placeholder="Commit SHA" className="border border-white/20 bg-black px-4 py-3 text-sm outline-none focus:border-red-400" /><button disabled={launching || !commitSha.trim()} className="bg-red-600 px-4 py-3 text-xs uppercase tracking-[0.16em] transition hover:bg-red-500 disabled:opacity-50">{launching ? 'Starting…' : 'Attack release'}</button></form></div>
          <div className="mt-8 flex items-center justify-between"><div><p className="text-[10px] uppercase tracking-[0.2em] text-white/45">Release history</p><h3 className="mt-2 text-lg">Baselines and regressions</h3></div><span className="text-xs text-white/40">{releases.length} release{releases.length === 1 ? '' : 's'}</span></div>
          <div className="mt-4 space-y-3">{releases.map((release) => <article key={release.release_id} className="border border-white/10 bg-white/[0.02] p-5"><div className="flex flex-wrap items-start justify-between gap-4"><div><p className="font-mono text-sm text-white">{release.commit_sha}</p><p className="mt-1 text-[10px] uppercase tracking-[0.16em] text-white/45">{release.environment} · {release.status}</p></div><span className={`border px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.16em] ${decisionStyle(release.decision)}`}>{release.decision ?? 'running'}</span></div><div className="mt-5 grid gap-3 text-xs text-white/60 sm:grid-cols-4"><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">New findings</span>{release.comparison.new_finding_ids?.length ?? 0}</div><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">Known findings</span>{release.comparison.known_finding_ids?.length ?? 0}</div><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">Coverage</span>{release.summary.coverage ?? '—'}{release.summary.coverage !== undefined ? '%' : ''}</div><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">Security score</span>{release.summary.security_score ?? '—'}</div></div>{release.comparison.baseline_established && <p className="mt-4 text-xs text-emerald-200">Safe baseline established for future regression checks.</p>}{release.summary.error && <p className="mt-4 text-xs text-red-200">{release.summary.error}</p>}</article>)}{!releases.length && <div className="border border-dashed border-white/15 p-8 text-sm text-white/45">No releases yet. Enter a preview commit SHA to create the baseline.</div>}</div>
        </section>}
      </div>
    </main>
  )
}
