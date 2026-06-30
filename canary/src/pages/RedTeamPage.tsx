import React, { useState, useEffect, useCallback } from 'react'
import Navbar from '../components/Navbar'

// Backend connection — empty string = relative URL, handled by nginx proxy
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const _env = (import.meta as any).env as Record<string, string>
const API_BASE  = _env.VITE_API_URL  || ''
const API_TOKEN = _env.VITE_API_TOKEN || ''
const authHeader = () => ({ 'Authorization': `Bearer ${API_TOKEN}`, 'Content-Type': 'application/json' })

// ─── Types ────────────────────────────────────────────────────────────────────

interface Incident {
  id: string
  run_id: string
  timestamp: string
  agent: string
  type: string
  riskScore: number
  status: string
  details: string
}

interface Attack {
  id: number
  attempt_number: number
  strategy_type: string
  success: boolean
  severity: string
  score: number
  score_threshold: number
  prompt: string
  response: string
  timestamp: string | null
  finding_id: string | null
  target_id: string | null
}

interface Patch {
  id: number
  patch_type: string
  target_component: string
  diff: string
  applied: boolean
  retest_passed: boolean
}

interface RunDetail {
  run_id: string
  target_id: string
  status: string
  start_time: string | null
  end_time: string | null
  total_attacks: number
  successful_attacks: number
  success_rate: number
  attacks: Attack[]
  patches: Patch[]
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ATTACK_ICONS: Record<string, string> = {
  'Prompt Injection':   'PI',
  'Tool Misuse':        'TM',
  'Data Exfiltration':  'DE',
  'Privilege Escalation': 'PE',
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function riskBarColor(score: number): string {
  if (score > 70) return 'bg-red-500'
  if (score >= 40) return 'bg-orange-400'
  return 'bg-white/30'
}

function riskTextColor(score: number): string {
  if (score > 70) return 'text-red-400'
  if (score >= 40) return 'text-orange-400'
  return 'text-white/40'
}

function statusBadgeClass(status: string): string {
  if (status === 'Critical') return 'bg-red-950/30 text-red-400 border border-red-600/20'
  if (status === 'Warning')  return 'text-orange-400'
  return 'text-white/30'
}

function humanStrategy(s: string): string {
  const MAP: Record<string, string> = {
    prompt_injection:        'Prompt Injection',
    tool_misuse:             'Tool Misuse',
    indirect_injection:      'Data Exfiltration',
    retrieval_poisoning:     'Retrieval Poisoning',
    jailbreak:               'Privilege Escalation',
    sensitive_data_exposure: 'Data Exfiltration',
    memory_poisoning:        'Memory Poisoning',
    workflow_manipulation:   'Agent DoS',
    instruction_hierarchy:   'Goal Hijacking',
  }
  return MAP[s] ?? s.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

// ─── Run Detail Panel ─────────────────────────────────────────────────────────

function RunDetailPanel({ detail }: { detail: RunDetail }) {
  return (
    <div>
      {/* Run metadata grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-8 gap-y-4 mb-6">
        {([
          ['Run ID',       detail.run_id],
          ['Target',       detail.target_id],
          ['Status',       detail.status],
          ['Start Time',   detail.start_time  ?? '—'],
          ['End Time',     detail.end_time    ?? '—'],
          ['Success Rate', `${(detail.success_rate * 100).toFixed(1)}%`],
        ] as [string, string][]).map(([label, value]) => (
          <div key={label} className="flex flex-col gap-0.5">
            <span className="text-white/20 text-[9px] uppercase tracking-wider">{label}</span>
            <span className="text-white/70 text-xs font-mono">{value}</span>
          </div>
        ))}
      </div>

      {/* Summary row */}
      <div className="flex gap-6 border border-white/10 bg-white/[0.02] px-4 py-3 mb-6">
        <div className="flex flex-col gap-0.5">
          <span className="text-white/20 text-[9px] uppercase tracking-wider">Total Attacks</span>
          <span className="text-white/70 text-xs font-mono">{detail.total_attacks}</span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="text-white/20 text-[9px] uppercase tracking-wider">Successful</span>
          <span className="text-red-400 text-xs font-mono">{detail.successful_attacks}</span>
        </div>
        <div className="flex flex-col gap-0.5">
          <span className="text-white/20 text-[9px] uppercase tracking-wider">Blocked</span>
          <span className="text-white/60 text-xs font-mono">{detail.total_attacks - detail.successful_attacks}</span>
        </div>
      </div>

      {/* Attacks table */}
      {detail.attacks.length > 0 && (
        <div className="mb-6">
          <div className="text-white/20 text-[9px] uppercase tracking-[0.2em] mb-3">Attacks</div>
          <div className="border border-white/[0.06]">
            {/* Table header */}
            <div className="grid grid-cols-[32px_1fr_140px_60px_1fr_80px] gap-3 px-3 py-2 border-b border-white/[0.06] bg-white/[0.01]">
              {['#', 'Strategy', 'Score / Threshold', 'Result', 'Prompt', 'Finding'].map(h => (
                <span key={h} className="text-white/20 text-[9px] uppercase tracking-[0.15em]">{h}</span>
              ))}
            </div>
            {detail.attacks.map(attack => (
              <div
                key={attack.id}
                className="grid grid-cols-[32px_1fr_140px_60px_1fr_80px] gap-3 items-start px-3 py-2.5 border-b border-white/[0.04] last:border-b-0 hover:bg-white/[0.01]"
              >
                {/* Attempt # */}
                <span className="text-white/30 text-[9px] font-mono mt-0.5">{attack.attempt_number}</span>

                {/* Strategy */}
                <span className="text-white/60 text-[10px] leading-relaxed">{humanStrategy(attack.strategy_type)}</span>

                {/* Score / threshold bar */}
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-1.5">
                    <div className="flex-1 h-[2px] bg-white/10 relative">
                      {/* Threshold marker */}
                      <div
                        className="absolute top-0 h-full w-[1px] bg-white/30"
                        style={{ left: `${Math.min(100, attack.score_threshold * 100)}%` }}
                      />
                      {/* Score fill */}
                      <div
                        className={`h-full ${attack.score > attack.score_threshold ? 'bg-red-500' : 'bg-white/30'}`}
                        style={{ width: `${Math.min(100, attack.score * 100)}%` }}
                      />
                    </div>
                  </div>
                  <span className="text-[9px] font-mono text-white/40">
                    {attack.score.toFixed(2)} / {attack.score_threshold.toFixed(2)}
                  </span>
                </div>

                {/* Success badge */}
                <span className={`text-[9px] uppercase tracking-wider px-1.5 py-0.5 ${
                  attack.success
                    ? 'bg-red-950/30 text-red-400 border border-red-600/20'
                    : 'text-white/30'
                }`}>
                  {attack.success ? 'HIT' : 'MISS'}
                </span>

                {/* Prompt excerpt */}
                <span className="text-white/40 text-[9px] font-mono leading-relaxed line-clamp-2">
                  {attack.prompt.length > 120 ? attack.prompt.slice(0, 120) + '…' : attack.prompt}
                </span>

                {/* Finding ID */}
                <span className="text-white/20 text-[9px] font-mono truncate">
                  {attack.finding_id ? attack.finding_id.slice(0, 8) : '—'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Patches list */}
      {detail.patches.length > 0 && (
        <div>
          <div className="text-white/20 text-[9px] uppercase tracking-[0.2em] mb-3">Patches</div>
          <div className="border border-white/[0.06]">
            {detail.patches.map(patch => (
              <div
                key={patch.id}
                className="flex items-center justify-between gap-4 px-3 py-2.5 border-b border-white/[0.04] last:border-b-0 hover:bg-white/[0.01]"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-white/60 text-[10px] uppercase tracking-wider shrink-0">{patch.patch_type}</span>
                  <span className="text-white/20 text-[9px]">·</span>
                  <span className="text-white/40 text-[9px] font-mono truncate">{patch.target_component}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className={`text-[9px] uppercase tracking-wider ${patch.applied ? 'text-white/50' : 'text-white/20'}`}>
                    {patch.applied ? 'Applied' : 'Pending'}
                  </span>
                  <span className={`text-[9px] uppercase tracking-wider px-1.5 py-0.5 border ${
                    patch.retest_passed
                      ? 'text-white/50 border-white/10'
                      : 'text-red-400/60 border-red-600/10'
                  }`}>
                    {patch.retest_passed ? 'Pass' : 'Fail'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

interface RedTeamPageProps {
  onBack: () => void
  onRunAudit: () => void
}

export default function RedTeamPage({ onBack, onRunAudit }: RedTeamPageProps) {
  const [incidents,        setIncidents]        = useState<Incident[]>([])
  const [loading,          setLoading]          = useState(true)
  const [error,            setError]            = useState<string | null>(null)
  const [expandedId,       setExpandedId]       = useState<string | null>(null)
  const [activeRunId,      setActiveRunId]      = useState<string | null>(null)
  const [runDetail,        setRunDetail]        = useState<RunDetail | null>(null)
  const [runDetailLoading, setRunDetailLoading] = useState(false)
  const [runDetailError,   setRunDetailError]   = useState<string | null>(null)

  // ── Fetch incidents ─────────────────────────────────────────────────────────
  const fetchIncidents = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/incidents`, {
        headers: authHeader(),
      })
      if (!res.ok) throw new Error(`Server responded ${res.status}`)
      const data: Incident[] = await res.json()
      setIncidents(data)
      setError(null)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchIncidents()
    const interval = setInterval(fetchIncidents, 30_000)
    return () => clearInterval(interval)
  }, [fetchIncidents])

  // ── Fetch run detail ────────────────────────────────────────────────────────
  const fetchRunDetail = useCallback(async (runId: string) => {
    setRunDetailLoading(true)
    setRunDetailError(null)
    setRunDetail(null)
    setActiveRunId(runId)
    try {
      const res = await fetch(`${API_BASE}/api/runs/${runId}`, {
        headers: authHeader(),
      })
      if (!res.ok) throw new Error(`Server responded ${res.status}`)
      const data: RunDetail = await res.json()
      setRunDetail(data)
    } catch (e) {
      setRunDetailError((e as Error).message)
    } finally {
      setRunDetailLoading(false)
    }
  }, [])

  // ── Toggle row expansion ────────────────────────────────────────────────────
  const toggleRow = (id: string) => {
    setExpandedId(prev => {
      if (prev === id) {
        // Collapsing — clear run detail if it belongs to this row
        const incident = incidents.find(i => i.id === id)
        if (incident && activeRunId === incident.run_id) {
          setActiveRunId(null)
          setRunDetail(null)
          setRunDetailError(null)
        }
        return null
      }
      return id
    })
  }

  // ── Derived stats ───────────────────────────────────────────────────────────
  const totalIncidents = incidents.length
  const criticalCount  = incidents.filter(i => i.status === 'Critical').length
  const blockedCount   = incidents.filter(i => i.status === 'Blocked').length
  const avgRisk = incidents.length > 0
    ? Math.round(incidents.reduce((sum, i) => sum + i.riskScore, 0) / incidents.length)
    : 0

  // ─── RENDER ─────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-black text-white font-mono">
      <Navbar onRunAudit={onRunAudit} onLogoClick={onBack} />

      {/* ── SECTION 01: LIVE INCIDENT FEED ── */}
      <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-16 border-b border-white/10 pt-36">

        {/* Section header + live badge */}
        <div className="flex items-center justify-between mb-10">
          <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase">
            // SECTION 01 — LIVE INCIDENT FEED
          </p>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse-red" />
            <span className="text-white/40 text-[9px] uppercase tracking-[0.25em]">LIVE</span>
          </div>
        </div>

        {/* Loading state */}
        {loading && (
          <div className="py-24 flex items-center justify-center gap-2">
            <span className="text-white/40 text-xs uppercase tracking-[0.3em]">Fetching incident feed</span>
            <span className="text-red-500 animate-blink text-sm leading-none">█</span>
          </div>
        )}

        {/* Error banner (still renders table below) */}
        {error && (
          <div className="mb-6 border border-red-600/30 bg-red-950/20 px-4 py-3 flex items-center gap-2">
            <span className="text-red-600/60 text-[9px] uppercase tracking-wider">Error</span>
            <span className="text-red-400 text-[10px] font-mono">{error}</span>
          </div>
        )}

        {/* Table */}
        {!loading && (
          <>
            {/* Column headers */}
            <div className="hidden sm:grid sm:grid-cols-[120px_1fr_1fr_160px_100px] gap-4 px-4 py-2 border-b border-white/[0.08]">
              {['Timestamp', 'Agent', 'Attack Type', 'Risk Score', 'Status'].map(h => (
                <span key={h} className="text-white/20 text-[9px] uppercase tracking-[0.2em]">{h}</span>
              ))}
            </div>

            {/* Empty state */}
            {incidents.length === 0 && !error && (
              <div className="py-24 text-center border-b border-white/[0.06]">
                <span className="text-white/30 text-xs uppercase tracking-[0.25em]">
                  No incidents recorded. Run an audit to begin.
                </span>
              </div>
            )}

            {/* Incident rows */}
            {incidents.map(incident => (
              <React.Fragment key={incident.id}>
                {/* Row */}
                <div
                  onClick={() => toggleRow(incident.id)}
                  className={`grid grid-cols-[1fr_auto] sm:grid-cols-[120px_1fr_1fr_160px_100px] gap-4 items-center px-4 py-3 border-b border-white/[0.06] cursor-pointer hover:bg-white/[0.02] transition-colors duration-150 ${
                    expandedId === incident.id ? 'bg-white/[0.02]' : ''
                  }`}
                >
                  {/* Timestamp */}
                  <span className="text-white/50 text-xs font-mono">{incident.timestamp}</span>

                  {/* Agent (hidden on mobile in compact layout) */}
                  <span className="hidden sm:block text-white/70 text-xs truncate">{incident.agent}</span>

                  {/* Attack type with icon prefix */}
                  <div className="hidden sm:flex items-center gap-2 min-w-0">
                    <span className="text-red-500/70 text-[9px] font-mono bg-red-950/20 border border-red-600/10 px-1 py-0.5 shrink-0">
                      {ATTACK_ICONS[incident.type] ?? '--'}
                    </span>
                    <span className="text-white/70 text-xs truncate">{incident.type}</span>
                  </div>

                  {/* Risk score bar + number */}
                  <div className="hidden sm:flex items-center gap-2">
                    <div className="flex-1 h-[2px] bg-white/10 max-w-[80px]">
                      <div
                        className={`h-full ${riskBarColor(incident.riskScore)} transition-all duration-500`}
                        style={{ width: `${incident.riskScore}%` }}
                      />
                    </div>
                    <span className={`text-[10px] font-mono shrink-0 ${riskTextColor(incident.riskScore)}`}>
                      {incident.riskScore}
                    </span>
                  </div>

                  {/* Status badge */}
                  <div className="flex items-center gap-2">
                    <span className={`text-[9px] uppercase tracking-wider px-2 py-0.5 ${statusBadgeClass(incident.status)}`}>
                      {incident.status}
                    </span>
                    {/* Mobile: expand indicator */}
                    <span className="sm:hidden text-white/20 text-[9px]">
                      {expandedId === incident.id ? '▲' : '▼'}
                    </span>
                  </div>
                </div>

                {/* Inline expansion */}
                {expandedId === incident.id && (
                  <div className="bg-white/[0.03] border border-white/10 mx-4 my-1 px-5 py-4">

                    {/* Mobile: show cols hidden above */}
                    <div className="flex flex-wrap gap-4 sm:hidden mb-4 pb-4 border-b border-white/[0.06]">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-white/20 text-[9px] uppercase tracking-wider">Agent</span>
                        <span className="text-white/70 text-xs">{incident.agent}</span>
                      </div>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-white/20 text-[9px] uppercase tracking-wider">Attack Type</span>
                        <div className="flex items-center gap-1.5">
                          <span className="text-red-500/70 text-[9px] font-mono bg-red-950/20 border border-red-600/10 px-1 py-0.5">
                            {ATTACK_ICONS[incident.type] ?? '--'}
                          </span>
                          <span className="text-white/70 text-xs">{incident.type}</span>
                        </div>
                      </div>
                      <div className="flex flex-col gap-0.5">
                        <span className="text-white/20 text-[9px] uppercase tracking-wider">Risk Score</span>
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-[2px] bg-white/10">
                            <div
                              className={`h-full ${riskBarColor(incident.riskScore)}`}
                              style={{ width: `${incident.riskScore}%` }}
                            />
                          </div>
                          <span className={`text-[10px] font-mono ${riskTextColor(incident.riskScore)}`}>
                            {incident.riskScore}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Details + View Run button */}
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="text-white/20 text-[9px] uppercase tracking-wider mb-2">Incident Detail</div>
                        <div className="text-white/70 text-xs leading-relaxed">{incident.details}</div>
                        <div className="mt-2 text-white/25 text-[9px] font-mono">
                          {incident.id} · run: {incident.run_id}
                        </div>
                      </div>
                      <button
                        onClick={(e) => { e.stopPropagation(); fetchRunDetail(incident.run_id) }}
                        className="shrink-0 px-4 py-2 border border-white/20 text-white/60 text-[10px] uppercase tracking-[0.15em] hover:border-white/40 hover:text-white transition-all duration-200"
                      >
                        View Run →
                      </button>
                    </div>

                    {/* Run detail panel */}
                    {activeRunId === incident.run_id && (
                      <div className="mt-5 border-t border-white/[0.06] pt-5">
                        {runDetailLoading && (
                          <div className="py-6 flex items-center gap-2">
                            <span className="text-white/40 text-[10px] uppercase tracking-wider">
                              Loading run {incident.run_id}
                            </span>
                            <span className="text-red-500 animate-blink text-sm leading-none">█</span>
                          </div>
                        )}
                        {runDetailError && !runDetailLoading && (
                          <div className="border border-red-600/30 bg-red-950/20 px-4 py-3">
                            <span className="text-red-400 text-[10px] uppercase tracking-wider">
                              Error: {runDetailError}
                            </span>
                          </div>
                        )}
                        {runDetail && runDetail.run_id === incident.run_id && !runDetailLoading && (
                          <RunDetailPanel detail={runDetail} />
                        )}
                      </div>
                    )}
                  </div>
                )}
              </React.Fragment>
            ))}
          </>
        )}
      </section>

      {/* ── SECTION 02: CAMPAIGN STATS ── */}
      <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-14">
        <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-8">
          // SECTION 02 — CAMPAIGN STATS
        </p>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {/* Total Incidents */}
          <div className="border border-white/10 bg-white/[0.02] p-5">
            <div className="text-white text-2xl font-bold mb-1">{totalIncidents}</div>
            <div className="text-white/30 text-[9px] uppercase tracking-[0.2em]">Total Incidents</div>
          </div>

          {/* Critical */}
          <div className="border border-red-600/30 bg-red-950/10 p-5">
            <div className="text-red-400 text-2xl font-bold mb-1">{criticalCount}</div>
            <div className="text-white/30 text-[9px] uppercase tracking-[0.2em]">Critical</div>
          </div>

          {/* Blocked */}
          <div className="border border-white/10 bg-white/[0.02] p-5">
            <div className="text-white text-2xl font-bold mb-1">{blockedCount}</div>
            <div className="text-white/30 text-[9px] uppercase tracking-[0.2em]">Blocked</div>
          </div>

          {/* Avg Risk Score */}
          <div className={`border p-5 ${avgRisk > 70 ? 'border-red-600/20 bg-red-950/10' : 'border-white/10 bg-white/[0.02]'}`}>
            <div className={`text-2xl font-bold mb-1 ${avgRisk > 70 ? 'text-red-400' : avgRisk >= 40 ? 'text-orange-400' : 'text-white'}`}>
              {avgRisk}
            </div>
            <div className="text-white/30 text-[9px] uppercase tracking-[0.2em]">Avg Risk Score</div>
          </div>
        </div>
      </section>
    </div>
  )
}
