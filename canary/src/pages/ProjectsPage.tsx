import { useEffect, useMemo, useState } from 'react'
import { acceptProjectBaseline, ApiError, getProjectBaselines, getProjectReleases, getProjects, getReleaseRegressions } from '../lib/api'
import type { CanaryProject, CanaryRelease } from '../lib/types'
import { CoverageSummary, DecisionBadge, RegressionCounts, SecurityScoreDelta } from '../features/releases/components'
import type { ReleaseRegression } from '../features/releases/release-domain'

const decisionStyle = (decision: CanaryRelease['decision']) => {
  if (decision === 'block') return 'border-red-500/40 bg-red-500/10 text-red-300'
  if (decision === 'warn') return 'border-amber-400/40 bg-amber-400/10 text-amber-200'
  if (decision === 'pass') return 'border-emerald-400/40 bg-emerald-400/10 text-emerald-200'
  return 'border-white/15 bg-white/5 text-white/50'
}

export default function ProjectsPage({ onBack }: { onBack: () => void }) {
  const [projects, setProjects] = useState<CanaryProject[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [releases, setReleases] = useState<CanaryRelease[]>([])
  const [baselines, setBaselines] = useState<unknown[]>([])
  const [selectedRelease, setSelectedRelease] = useState<CanaryRelease | null>(null)
  const [regressions, setRegressions] = useState<ReleaseRegression[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const selected = useMemo(() => projects.find((project) => project.project_id === selectedId) ?? null, [projects, selectedId])

  useEffect(() => {
    getProjects().then((items) => {
      setProjects(items)
      setSelectedId(items[0]?.project_id ?? '')
    }).catch((cause) => setError(cause instanceof ApiError ? cause.message : 'Canary API is unavailable'))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (!selectedId) return
    const load = () => getProjectReleases(selectedId).then(setReleases).catch((cause) => setError(cause instanceof ApiError ? cause.message : 'Unable to load releases'))
    void load()
    void getProjectBaselines(selectedId).then(setBaselines).catch(() => undefined)
    const timer = window.setInterval(() => void load(), 10_000)
    return () => window.clearInterval(timer)
  }, [selectedId])

  useEffect(() => {
    if (!selectedRelease) return
    void getReleaseRegressions(selectedRelease.release_id).then((items) => setRegressions(items as ReleaseRegression[])).catch(() => setRegressions([]))
  }, [selectedRelease])

  if (loading) return <main className="min-h-screen bg-black p-10 font-mono text-sm text-white/60">Loading CI security history…</main>

  return (
    <main className="min-h-screen bg-black px-6 py-8 font-mono text-white sm:px-10 md:px-16 lg:px-20">
      <header className="flex flex-wrap items-end justify-between gap-5 border-b border-white/10 pb-6">
        <div>
          <button onClick={onBack} className="text-xs uppercase tracking-[0.2em] text-white/50 hover:text-white">← Canary</button>
          <p className="mt-6 text-[10px] uppercase tracking-[0.24em] text-red-400">Security releases</p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight">PR evidence. Safe baseline. Clear gate.</h1>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-white/55">Every release is compared only with an explicitly accepted baseline for the same environment. The first assessment is evidence, not an implicit trust decision.</p>
        </div>
        <span className="border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-[10px] uppercase tracking-[0.18em] text-emerald-200">CI controlled</span>
      </header>
      {error && <p className="mt-6 border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-200">{error}</p>}
      {!projects.length ? <section className="mt-12 border border-dashed border-white/15 p-8 text-sm leading-6 text-white/55">No repositories have reported yet. Commit <code>canary.yaml</code>, add the Canary Action to a PR workflow, and the first passing run on <code>main</code> establishes the safe baseline.</section> : (
        <div className="mt-8 grid gap-8 lg:grid-cols-[270px_minmax(0,1fr)]">
          <aside className="border-r border-white/10 pr-6">
            <p className="text-[10px] uppercase tracking-[0.22em] text-white/40">Repositories</p>
            <div className="mt-4 space-y-2">{projects.map((project) => <button key={project.project_id} onClick={() => setSelectedId(project.project_id)} className={`w-full border p-4 text-left transition ${project.project_id === selectedId ? 'border-red-500/60 bg-red-500/10' : 'border-white/10 bg-white/[0.02] hover:border-white/30'}`}><strong className="block text-sm">{project.repository || project.name}</strong><span className="mt-2 block text-[10px] uppercase tracking-[0.16em] text-white/45">{project.environment} · {project.strategies.length} strategies</span></button>)}</div>
          </aside>
          {selected && <section>
            <div className="border border-white/10 bg-white/[0.02] p-6"><p className="text-[10px] uppercase tracking-[0.2em] text-white/45">Current target contract</p><h2 className="mt-3 text-xl font-medium">{selected.repository || selected.name}</h2><p className="mt-2 break-all text-xs text-white/55">{selected.endpoint}</p><p className="mt-5 text-[10px] uppercase tracking-[0.16em] text-white/45">Environment: {selected.environment} · Blocks new {selected.gate.block_on.join(' / ')} regressions</p><p className="mt-2 text-xs text-white/45">Accepted baselines: {baselines.length}</p></div>
            <div className="mt-8 flex items-end justify-between"><div><p className="text-[10px] uppercase tracking-[0.2em] text-white/45">Release history</p><h3 className="mt-2 text-lg">Baseline comparison</h3></div><span className="text-xs text-white/40">{releases.length} evaluated release{releases.length === 1 ? '' : 's'}</span></div>
            <div className="mt-4 space-y-3">{releases.map((release) => <article key={release.release_id} onClick={() => setSelectedRelease(release)} className={`cursor-pointer border p-5 transition ${selectedRelease?.release_id === release.release_id ? 'border-red-400/50 bg-red-500/[0.06]' : 'border-white/10 bg-white/[0.02] hover:border-white/25'}`}><div className="flex flex-wrap items-start justify-between gap-4"><div><p className="font-mono text-sm text-white">{release.commit_sha.slice(0, 12)}</p><p className="mt-1 text-[10px] uppercase tracking-[0.16em] text-white/45">{release.ref || release.environment} · {release.status}{release.is_baseline ? ' · accepted baseline' : ''}</p></div><span className={`border px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.16em] ${decisionStyle(release.decision)}`}>{release.decision ?? 'pending'}</span></div><div className="mt-5 grid gap-3 text-xs text-white/60 sm:grid-cols-5"><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">New</span>{release.comparison.new_regression_ids?.length ?? release.comparison.new_finding_ids?.length ?? 0}</div><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">Known</span>{release.comparison.known ?? release.comparison.known_finding_ids?.length ?? 0}</div><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">Coverage</span>{release.coverage?.percentage ?? release.summary.coverage ?? '—'}{(release.coverage?.percentage ?? release.summary.coverage) !== undefined ? '%' : ''}</div><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">Score</span>{release.candidate_score ?? release.summary.security_score ?? '—'}</div><div><span className="block text-[10px] uppercase tracking-[0.14em] text-white/35">Delta</span>{release.score_delta ?? '—'}</div></div>{!release.baseline_release_id && release.status === 'completed' && !release.is_baseline && <button onClick={(event) => { event.stopPropagation(); void acceptProjectBaseline(selected.project_id, release.release_id).then(() => getProjectBaselines(selected.project_id).then(setBaselines)) }} className="mt-4 border border-cyan-400/40 px-3 py-2 text-[10px] uppercase tracking-[0.16em] text-cyan-200 hover:bg-cyan-400/10">Accept as {release.environment} baseline</button>}{!release.baseline_release_id && <p className="mt-4 text-xs text-amber-200">Assessment only — no accepted baseline existed for this environment.</p>}{release.summary.error && <p className="mt-4 text-xs text-red-200">{release.summary.error}</p>}</article>)}{!releases.length && <div className="border border-dashed border-white/15 p-8 text-sm text-white/45">No releases yet. CI writes this history after each PR or main commit.</div>}</div>
            {selectedRelease && <section className="mt-8 border border-white/10 bg-black/40 p-6"><div className="flex flex-wrap items-center justify-between gap-4"><div><p className="text-[10px] uppercase tracking-[0.2em] text-red-400">Agent Canary release evidence</p><h3 className="mt-2 font-mono text-lg">{selectedRelease.commit_sha.slice(0, 12)}</h3><p className="mt-1 text-xs text-white/45">Baseline {selectedRelease.baseline_release_id?.slice(0, 12) || 'none'} · {selectedRelease.environment}</p></div><DecisionBadge decision={selectedRelease.decision} /></div><div className="mt-6 grid gap-4 md:grid-cols-3"><SecurityScoreDelta baseline={selectedRelease.baseline_score ?? null} candidate={selectedRelease.candidate_score ?? selectedRelease.summary.security_score ?? null} /><CoverageSummary coverage={{ configuredStrategies: selectedRelease.coverage?.configured_strategies ?? 0, attemptedStrategies: selectedRelease.coverage?.attempted_strategies ?? 0, successfulStrategies: selectedRelease.coverage?.successful_strategies ?? 0, failedStrategies: selectedRelease.coverage?.failed_strategies ?? 0, skippedStrategies: selectedRelease.coverage?.skipped_strategies ?? 0, plannedAttackCases: selectedRelease.coverage?.planned_attack_cases ?? 0, attemptedAttackCases: selectedRelease.coverage?.attempted_attack_cases ?? 0, completedAttackCases: selectedRelease.coverage?.completed_attack_cases ?? 0 }} /><RegressionCounts counts={{ regressions: selectedRelease.comparison.new_regression_ids?.length ?? 0, known: selectedRelease.comparison.known ?? 0, resolved: selectedRelease.comparison.resolved ?? 0, clean: selectedRelease.comparison.clean ?? 0, indeterminate: selectedRelease.comparison.indeterminate ?? 0 }} /></div><div className="mt-6 space-y-3">{regressions.map((item) => <article key={item.regression_id} className="border border-red-400/20 bg-red-400/[0.04] p-4"><div className="flex flex-wrap justify-between gap-3"><strong className="text-sm uppercase tracking-[0.14em]">{item.classification}</strong><span className="text-xs uppercase text-white/50">{item.severity || 'unclassified'}</span></div><p className="mt-2 text-xs leading-5 text-white/65">{item.reason}</p><div className="mt-3 grid gap-3 text-xs md:grid-cols-2"><pre className="overflow-auto whitespace-pre-wrap border border-white/10 p-3 text-emerald-200">Baseline{`\\n`}{JSON.stringify(item.baseline_evidence, null, 2)}</pre><pre className="overflow-auto whitespace-pre-wrap border border-white/10 p-3 text-amber-200">Candidate{`\\n`}{JSON.stringify(item.candidate_evidence, null, 2)}</pre></div></article>)}{!regressions.length && <p className="text-xs text-white/45">No paired regressions were persisted for this release.</p>}</div></section>}
          </section>}
        </div>
      )}
    </main>
  )
}
