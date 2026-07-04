import { useState, useEffect, useCallback } from 'react'
import Navbar from '../components/Navbar'

// Backend connection — empty string = relative URL, handled by nginx proxy
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const _env = (import.meta as any).env as Record<string, string>
const API_BASE  = _env.VITE_API_URL  || ''
const API_TOKEN = _env.VITE_API_TOKEN || ''
const authHeader = () => ({ 'Authorization': `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' })

// ─── Types ────────────────────────────────────────────────────────────────────

interface Finding {
  finding_id: string
  target_id: string
  component: string
  strategy: string
  asi_class: string
  atlas_technique: string
  severity: string   // critical | high | medium | low | info
  status: string     // open | wont_fix | false_positive | inconclusive
  first_seen_run: string
  last_seen_run: string
  seen_in_runs: string[]
  created_at: string | null
  updated_at: string | null
}

interface LatestVerdict {
  verdict_id: string
  verdict: string        // confirmed | unconfirmed | inconclusive | failed
  confidence: string     // high | medium | low
  threshold_used: number
  verdict_path: string
  rationale: string | null
  timestamp: string | null
}

interface Attempt {
  id: number
  run_id: string
  attempt_number: number
  strategy_type: string
  success: boolean
  severity: string
  score: number
  timestamp: string | null
}

// ─── Constants ────────────────────────────────────────────────────────────────

const STATUS_TRANSITIONS: Record<string, string[]> = {
  open:           ['wont_fix', 'false_positive', 'inconclusive'],
  inconclusive:   ['open', 'wont_fix', 'false_positive'],
  wont_fix:       [],
  false_positive: [],
}

const RATIONALE_REQUIRED = new Set(['wont_fix', 'false_positive'])

const ALL_SEVERITIES  = ['critical', 'high', 'medium', 'low']
const ALL_STATUSES    = ['open', 'wont_fix', 'false_positive', 'inconclusive']
const ALL_ASI_CLASSES = ['ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05', 'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10']

const PAGE_SIZE = 50

// ─── Helpers ─────────────────────────────────────────────────────────────────

function severityBadgeClass(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical': return 'text-red-400 bg-red-950/20 border border-red-600/30'
    case 'high':     return 'text-orange-400 bg-orange-950/15 border border-orange-600/20'
    case 'medium':   return 'text-yellow-400/80 bg-yellow-950/10 border border-yellow-600/15'
    default:         return 'text-white/40 bg-white/[0.04] border border-white/10'
  }
}

function statusPillClass(status: string): string {
  switch (status) {
    case 'open':           return 'text-red-400 bg-red-950/30 border border-red-600/30'
    case 'wont_fix':       return 'text-white/30 bg-white/[0.02] border border-white/10'
    case 'false_positive': return 'text-white/20 bg-white/[0.02] border border-white/10'
    case 'inconclusive':   return 'text-white/50 bg-white/[0.04] border border-white/10'
    default:               return 'text-white/40 bg-white/[0.04] border border-white/10'
  }
}

function formatStatus(status: string): string {
  return status.replace(/_/g, ' ').toUpperCase()
}

// ─── AttemptsTable ────────────────────────────────────────────────────────────

function AttemptsTable({ findingId }: { findingId: string }) {
  const [attempts, setAttempts] = useState<Attempt[]>([])
  const [loading, setLoading]   = useState(true)
  const [err, setErr]           = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setErr(null)
    fetch(`${API_BASE}/api/findings/${findingId}/attempts`, { headers: authHeader() })
      .then(r => { if (!r.ok) throw new Error(`${r.status}`); return r.json() })
      .then((data: Attempt[]) => {
        if (!cancelled) { setAttempts(Array.isArray(data) ? data : []); setLoading(false) }
      })
      .catch((e: unknown) => {
        if (!cancelled) { setErr(e instanceof Error ? e.message : 'Error'); setLoading(false) }
      })
    return () => { cancelled = true }
  }, [findingId])

  return (
    <div className="mt-3 pt-3 border-t border-white/[0.06]">
      <p className="text-white/30 text-[9px] uppercase tracking-wider mb-2">
        Attempts{!loading && !err ? ` (${attempts.length})` : ''}
      </p>

      {loading && (
        <span className="text-[9px] text-white/25 uppercase tracking-wider">Loading...</span>
      )}
      {!loading && err && (
        <span className="text-[9px] text-red-400">Failed to load: {err}</span>
      )}
      {!loading && !err && attempts.length === 0 && (
        <span className="text-[9px] text-white/20 uppercase tracking-wider">No attempts recorded</span>
      )}
      {!loading && !err && attempts.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                {['#', 'Run ID', 'Strategy', 'Score', 'Success', 'Time'].map(h => (
                  <th key={h} className="text-left text-white/20 text-[9px] uppercase tracking-wider py-1 pr-4 font-normal whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {attempts.map(a => (
                <tr key={a.id} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors">
                  <td className="py-1 pr-4 text-white/30 text-[9px] font-mono">{a.attempt_number}</td>
                  <td className="py-1 pr-4 text-white/50 text-[9px] font-mono">
                    {a.run_id ? `${a.run_id.slice(0, 8)}…` : '—'}
                  </td>
                  <td className="py-1 pr-4 text-white/50 text-[9px] font-mono whitespace-nowrap">
                    {a.strategy_type || '—'}
                  </td>
                  <td className="py-1 pr-4 text-white/60 text-[9px] font-mono">
                    {(a.score * 100).toFixed(0)}%
                  </td>
                  <td className="py-1 pr-4 text-[9px] font-mono">
                    <span className={a.success ? 'text-red-400' : 'text-white/25'}>
                      {a.success ? 'YES' : 'NO'}
                    </span>
                  </td>
                  <td className="py-1 text-white/25 text-[9px] font-mono whitespace-nowrap">
                    {a.timestamp ? a.timestamp.slice(0, 10) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── TransitionPanel ──────────────────────────────────────────────────────────

function TransitionPanel({ finding, onRefresh }: { finding: Finding; onRefresh: () => void }) {
  const nextStates = STATUS_TRANSITIONS[finding.status] ?? []
  const [selected,   setSelected]   = useState('')
  const [reviewerId, setReviewerId] = useState('')
  const [rationale,  setRationale]  = useState('')
  const [loading,    setLoading]    = useState(false)
  const [err,        setErr]        = useState<string | null>(null)

  const needsRationale = RATIONALE_REQUIRED.has(selected)
  const canSubmit = selected !== '' && (!needsRationale || (reviewerId.trim() !== '' && rationale.trim() !== ''))

  const handleCancel = () => { setSelected(''); setReviewerId(''); setRationale(''); setErr(null) }

  const handleSubmit = async () => {
    if (!canSubmit || loading) return
    setLoading(true)
    setErr(null)
    try {
      const body: Record<string, string | boolean> = { status: selected }
      if (needsRationale) { body.reviewer_id = reviewerId; body.rationale = rationale }
      const res = await fetch(`${API_BASE}/api/findings/${finding.finding_id}/status`, {
        method: 'PUT',
        headers: authHeader(),
        body: JSON.stringify(body),
      })
      if (!res.ok) throw new Error(`Backend responded ${res.status}`)
      handleCancel()
      onRefresh()
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : 'Transition failed')
    } finally {
      setLoading(false)
    }
  }

  if (nextStates.length === 0) {
    return (
      <div className="mt-3 pt-3 border-t border-white/[0.06]">
        <span className="text-[9px] text-white/15 uppercase tracking-wider">Terminal state — no further transitions</span>
      </div>
    )
  }

  return (
    <div className="mt-3 pt-3 border-t border-white/[0.06]">
      <p className="text-white/30 text-[9px] uppercase tracking-wider mb-2">Transition Status</p>

      {/* Next-state selector pills */}
      <div className="flex flex-wrap gap-1.5 mb-2">
        {nextStates.map(s => (
          <button
            key={s}
            onClick={() => { setErr(null); setSelected(selected === s ? '' : s) }}
            className={`px-2.5 py-1 text-[9px] uppercase tracking-[0.1em] transition-all duration-150 ${
              selected === s
                ? statusPillClass(s)
                : 'border border-white/10 text-white/30 hover:border-white/25 hover:text-white/50'
            }`}
          >
            {formatStatus(s)}
          </button>
        ))}
      </div>

      {/* Rationale form — required for wont_fix / false_positive */}
      {selected && needsRationale && (
        <div className="flex flex-col gap-2 mt-2">
          <input
            type="text"
            value={reviewerId}
            onChange={e => setReviewerId(e.target.value)}
            placeholder="Reviewer ID"
            className="bg-white/[0.03] border border-white/15 text-white text-[10px] px-3 py-2 placeholder:text-white/20 outline-none focus:border-white/30 transition-colors font-mono"
          />
          <textarea
            value={rationale}
            onChange={e => setRationale(e.target.value)}
            placeholder="Rationale for this transition..."
            rows={2}
            className="bg-white/[0.03] border border-white/15 text-white text-[10px] px-3 py-2 placeholder:text-white/20 outline-none focus:border-white/30 transition-colors font-mono resize-none"
          />
        </div>
      )}

      {/* Confirm / cancel row */}
      {selected && (
        <div className="flex items-center gap-3 mt-2 flex-wrap">
          <button
            onClick={handleSubmit}
            disabled={!canSubmit || loading}
            className="px-4 py-1.5 bg-white/10 text-white text-[9px] uppercase tracking-[0.15em] hover:bg-white/20 disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-150"
          >
            {loading ? 'Updating...' : 'Confirm →'}
          </button>
          <button
            onClick={handleCancel}
            className="px-3 py-1.5 text-[9px] text-white/30 uppercase tracking-[0.1em] hover:text-white/50 transition-colors"
          >
            Cancel
          </button>
          {err && <span className="text-[9px] text-red-400">{err}</span>}
        </div>
      )}
    </div>
  )
}

// ─── VerdictBadge ─────────────────────────────────────────────────────────────

function VerdictBadge({ findingId }: { findingId: string }) {
  const [verdict, setVerdict] = useState<LatestVerdict | null>(null)

  useEffect(() => {
    fetch(`${API_BASE}/api/findings/${findingId}`, { headers: authHeader() })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.latest_verdict) setVerdict(data.latest_verdict)
      })
      .catch(() => {})
  }, [findingId])

  if (!verdict) return null

  const verdictColor =
    verdict.verdict === 'confirmed'    ? 'text-red-400 border-red-600/30 bg-red-950/20' :
    verdict.verdict === 'unconfirmed'  ? 'text-orange-400 border-orange-600/20 bg-orange-950/10' :
    verdict.verdict === 'inconclusive' ? 'text-white/40 border-white/10 bg-white/[0.03]' :
                                         'text-white/25 border-white/[0.06] bg-transparent'

  const confDot =
    verdict.confidence === 'high'   ? 'bg-red-500' :
    verdict.confidence === 'medium' ? 'bg-orange-400' : 'bg-white/30'

  return (
    <div className={`flex items-center gap-2 px-2 py-1 border text-[9px] font-mono w-fit ${verdictColor}`}>
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${confDot}`} />
      <span className="uppercase tracking-wider">{verdict.verdict}</span>
      <span className="text-white/20">·</span>
      <span className="text-white/30">{verdict.confidence} conf</span>
      <span className="text-white/20">·</span>
      <span className="text-white/30">{verdict.verdict_path}</span>
    </div>
  )
}

// ─── FindingCard ──────────────────────────────────────────────────────────────

function FindingCard({ finding, index, onRefresh }: { finding: Finding; index: number; onRefresh: () => void }) {
  const [showAttempts, setShowAttempts] = useState(false)
  const runsCount = (finding.seen_in_runs ?? []).length

  return (
    <div
      className={`border p-5 relative hover:border-white/20 transition-colors duration-200 animate-report ${
        finding.severity.toLowerCase() === 'critical'
          ? 'border-red-600/40 bg-red-950/10'
          : 'border-white/10 bg-white/[0.02]'
      }`}
      style={{ animationDelay: `${Math.min(index, 8) * 60}ms` }}
    >
      {/* ── Header row ── */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex flex-col gap-0.5 min-w-0 pr-3">
          <span className="text-[9px] text-red-500/70 uppercase tracking-[0.2em] font-mono">
            {finding.asi_class || '—'}
          </span>
          <span className="text-white text-[10px] uppercase tracking-[0.1em] font-medium leading-snug truncate">
            {finding.strategy || '—'}
          </span>
          <span className="text-white/35 text-[9px] font-mono truncate">{finding.component || '—'}</span>
        </div>
        <div className="flex flex-col items-end gap-1.5 shrink-0">
          <span className={`text-[9px] uppercase tracking-wider px-2 py-0.5 ${severityBadgeClass(finding.severity)}`}>
            {finding.severity.toUpperCase()}
          </span>
          {finding.atlas_technique && (
            <span className="text-white/20 text-[9px] font-mono">{finding.atlas_technique}</span>
          )}
        </div>
      </div>

      {/* ── Status + run badge ── */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <span className={`text-[9px] uppercase tracking-[0.1em] px-2 py-0.5 ${statusPillClass(finding.status)}`}>
          {formatStatus(finding.status)}
        </span>
        <span className="text-white/25 text-[9px] font-mono border border-white/[0.06] px-2 py-0.5">
          {runsCount} run{runsCount !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Latest evaluator verdict */}
      <div className="mb-3">
        <VerdictBadge findingId={finding.finding_id} />
      </div>

      {/* ── Run IDs ── */}
      <div className="flex gap-5 mb-3">
        <div className="flex flex-col gap-0.5">
          <span className="text-white/20 text-[9px] uppercase tracking-wider">First Seen</span>
          <span className="text-white/45 text-[9px] font-mono truncate max-w-[120px]">
            {finding.first_seen_run ? `${finding.first_seen_run.slice(0, 12)}…` : '—'}
          </span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="text-white/20 text-[9px] uppercase tracking-wider">Last Seen</span>
          <span className="text-white/45 text-[9px] font-mono truncate max-w-[120px]">
            {finding.last_seen_run ? `${finding.last_seen_run.slice(0, 12)}…` : '—'}
          </span>
        </div>
      </div>

      {/* ── Attempts toggle ── */}
      <button
        onClick={() => setShowAttempts(v => !v)}
        className="flex items-center gap-1.5 text-[9px] text-white/30 uppercase tracking-[0.15em] hover:text-white/55 transition-colors"
      >
        <span
          className="inline-block transition-transform duration-200"
          style={{ transform: showAttempts ? 'rotate(90deg)' : 'rotate(0deg)' }}
        >
          ▶
        </span>
        {showAttempts ? 'Hide Attempts' : 'View Attempts'}
      </button>

      {showAttempts && <AttemptsTable findingId={finding.finding_id} />}

      {/* ── Status transition ── */}
      <TransitionPanel finding={finding} onRefresh={onRefresh} />

      {/* ── Finding ID watermark ── */}
      <div className="absolute bottom-3 right-4 text-white/10 text-[9px] font-mono pointer-events-none select-none">
        {finding.finding_id}
      </div>
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

interface FindingsPageProps {
  onBack: () => void
  onRunAudit?: () => void
  onRedTeam?: () => void
}

export default function FindingsPage({ onBack, onRunAudit, onRedTeam }: FindingsPageProps) {
  const [findings,     setFindings]     = useState<Finding[]>([])
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState<string | null>(null)
  const [page,         setPage]         = useState(1)
  const [hasMore,      setHasMore]      = useState(false)
  const [loadingMore,  setLoadingMore]  = useState(false)

  const [filterSeverity,  setFilterSeverity]  = useState('all')
  const [filterStatus,    setFilterStatus]    = useState('all')
  const [filterAsiClass,  setFilterAsiClass]  = useState('all')

  // Derived stats (from loaded findings)
  const total             = findings.length
  const openCount         = findings.filter(f => f.status === 'open').length
  const criticalCount     = findings.filter(f => f.severity.toLowerCase() === 'critical').length

  // ── Fetch helpers ───────────────────────────────────────────────────────────

  const buildQuery = useCallback((pageNum: number) => {
    const p = new URLSearchParams()
    if (filterSeverity !== 'all') p.set('severity', filterSeverity)
    if (filterStatus   !== 'all') p.set('status',   filterStatus)
    if (filterAsiClass !== 'all') p.set('asi_class', filterAsiClass)
    p.set('page',      String(pageNum))
    p.set('page_size', String(PAGE_SIZE))
    return p.toString()
  }, [filterSeverity, filterStatus, filterAsiClass])

  const fetchPage = useCallback(async (pageNum: number, reset: boolean) => {
    if (reset) { setLoading(true); setError(null) }
    else setLoadingMore(true)

    try {
      const res = await fetch(`${API_BASE}/api/findings?${buildQuery(pageNum)}`, { headers: authHeader() })
      if (!res.ok) throw new Error(`Backend responded ${res.status}`)
      const data: Finding[] = await res.json()
      const arr = Array.isArray(data) ? data : []
      setFindings(prev => reset ? arr : [...prev, ...arr])
      setHasMore(arr.length === PAGE_SIZE)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to fetch findings')
      if (reset) setFindings([])
    } finally {
      if (reset) setLoading(false)
      else setLoadingMore(false)
    }
  }, [buildQuery])

  // Re-fetch whenever filters change
  useEffect(() => {
    setPage(1)
    fetchPage(1, true)
  }, [filterSeverity, filterStatus, filterAsiClass, fetchPage])

  const handleLoadMore = () => {
    const next = page + 1
    setPage(next)
    fetchPage(next, false)
  }

  // Called after a successful status PUT — re-fetches from page 1
  const handleRefresh = useCallback(() => {
    setPage(1)
    fetchPage(1, true)
  }, [fetchPage])

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-black text-white font-mono">
      <Navbar onLogoClick={onBack} onRunAudit={onRunAudit} onRedTeam={onRedTeam} />

      {/* ── HEADER ── */}
      <section className="px-6 sm:px-10 md:px-16 lg:px-20 pt-36 pb-8 border-b border-white/10">
        <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-6">
          // FINDINGS — MANAGEMENT
        </p>
        <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
          <div>
            <h1 className="text-white text-xl font-light tracking-[0.1em] uppercase mb-1">Findings</h1>
            <p className="text-white/30 text-[10px] uppercase tracking-wider">
              Red-team vulnerability tracking &amp; triage
            </p>
          </div>
          {error && (
            <p className="text-red-400 text-[10px] uppercase tracking-wider flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0 animate-pulse-red" />
              Backend unreachable — showing cached data or empty state.
            </p>
          )}
        </div>
      </section>

      {/* ── STATS ── */}
      <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-6 border-b border-white/10">
        <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-4">// STATS — OVERVIEW</p>
        <div className="flex flex-wrap gap-3">
          {[
            { label: 'Total',          value: total,              color: 'text-white' },
            { label: 'Open',           value: openCount,          color: 'text-red-400' },
            { label: 'Critical',       value: criticalCount,      color: 'text-red-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="border border-white/10 bg-white/[0.02] px-5 py-3 flex flex-col gap-1 min-w-[96px]">
              <span className={`text-xl font-light ${loading ? 'text-white/20' : color}`}>
                {loading ? '—' : value}
              </span>
              <span className="text-white/25 text-[9px] uppercase tracking-wider">{label}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── FILTERS ── */}
      <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-6 border-b border-white/10">
        <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-5">// FILTERS</p>
        <div className="flex flex-col gap-5">

          {/* Severity */}
          <div className="flex flex-col gap-2">
            <span className="text-white/30 text-[9px] uppercase tracking-wider">Severity</span>
            <div className="flex flex-wrap gap-1.5">
              {['all', ...ALL_SEVERITIES].map(s => (
                <button
                  key={s}
                  onClick={() => setFilterSeverity(s)}
                  className={`px-3 py-1 text-[9px] uppercase tracking-[0.12em] transition-all duration-150 ${
                    filterSeverity === s
                      ? s === 'all' ? 'bg-white text-black border border-white' : severityBadgeClass(s)
                      : 'border border-white/10 text-white/30 hover:border-white/25 hover:text-white/50'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Status */}
          <div className="flex flex-col gap-2">
            <span className="text-white/30 text-[9px] uppercase tracking-wider">Status</span>
            <div className="flex flex-wrap gap-1.5">
              {['all', ...ALL_STATUSES].map(s => (
                <button
                  key={s}
                  onClick={() => setFilterStatus(s)}
                  className={`px-3 py-1 text-[9px] uppercase tracking-[0.1em] transition-all duration-150 ${
                    filterStatus === s
                      ? s === 'all' ? 'bg-white text-black border border-white' : statusPillClass(s)
                      : 'border border-white/10 text-white/30 hover:border-white/25 hover:text-white/50'
                  }`}
                >
                  {s === 'all' ? 'All' : formatStatus(s)}
                </button>
              ))}
            </div>
          </div>

          {/* ASI Class */}
          <div className="flex flex-col gap-2">
            <span className="text-white/30 text-[9px] uppercase tracking-wider">ASI Class</span>
            <div className="flex flex-wrap gap-1.5">
              {['all', ...ALL_ASI_CLASSES].map(a => (
                <button
                  key={a}
                  onClick={() => setFilterAsiClass(a)}
                  className={`px-3 py-1 text-[9px] uppercase tracking-[0.1em] transition-all duration-150 ${
                    filterAsiClass === a
                      ? a === 'all'
                        ? 'bg-white text-black border border-white'
                        : 'border border-red-600/40 bg-red-950/20 text-red-400'
                      : 'border border-white/10 text-white/30 hover:border-white/25 hover:text-white/50'
                  }`}
                >
                  {a === 'all' ? 'All' : a}
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── FINDINGS LIST ── */}
      <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-8">
        <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-6">
          // FINDINGS —{' '}
          {loading ? '...' : `${total} RESULT${total !== 1 ? 'S' : ''}`}
        </p>

        {/* Loading skeleton */}
        {loading && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className="border border-white/10 bg-white/[0.02] p-5 h-48 animate-pulse"
                style={{ animationDelay: `${i * 80}ms` }}
              />
            ))}
          </div>
        )}

        {/* Error + no data */}
        {!loading && error && findings.length === 0 && (
          <div className="flex items-center justify-center gap-2.5 py-20">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
            <span className="text-red-400 text-[10px] uppercase tracking-wider">
              Backend unreachable — showing cached data or empty state.
            </span>
          </div>
        )}

        {/* Empty state */}
        {!loading && !error && findings.length === 0 && (
          <div className="flex flex-col items-center justify-center py-24 gap-2">
            <p className="text-white/20 text-[10px] uppercase tracking-[0.3em]">
              No findings match the current filters.
            </p>
          </div>
        )}

        {/* Cards grid */}
        {!loading && findings.length > 0 && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {findings.map((f, i) => (
              <FindingCard
                key={f.finding_id}
                finding={f}
                index={i}
                onRefresh={handleRefresh}
              />
            ))}
          </div>
        )}

        {/* Load more */}
        {!loading && hasMore && (
          <div className="flex justify-center mt-8">
            <button
              onClick={handleLoadMore}
              disabled={loadingMore}
              className="px-8 py-3 border border-white/20 text-white/60 text-[10px] uppercase tracking-[0.2em] hover:border-white/40 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-200"
            >
              {loadingMore ? 'Loading...' : 'Load More'}
            </button>
          </div>
        )}

        {/* Load-more error (findings already visible) */}
        {!loading && error && findings.length > 0 && (
          <div className="flex items-center justify-center gap-2 mt-6">
            <span className="w-1 h-1 rounded-full bg-red-500 shrink-0" />
            <span className="text-red-400 text-[10px] uppercase tracking-wider">
              Backend unreachable — showing cached data or empty state.
            </span>
          </div>
        )}
      </section>
    </div>
  )
}
