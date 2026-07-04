import React, { useState, useEffect, useCallback } from 'react'
import Navbar from '../components/Navbar'
import { getTargetCoverage, getTargetTrends, ApiError } from '../lib/api'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Coverage {
  target_id: string
  tested_classes: string[]
  untested_classes: string[]
  open_findings_by_class: Record<string, number>
  total_findings: number
  open_findings: number
}

interface TrendEntry {
  date: string
  strategy: string
  attempts: number
  successes: number
  success_rate: number
}

interface DefensesPageProps {
  onBack: () => void
  onRunAudit?: () => void
  onFindings?: () => void
  onRedTeam?: () => void
  onConsole?: () => void
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ASI_CLASSES = [
  { code: 'ASI01', name: 'Prompt Injection' },
  { code: 'ASI02', name: 'Memory Poisoning' },
  { code: 'ASI03', name: 'Tool & Plugin Abuse' },
  { code: 'ASI04', name: 'Privilege Escalation' },
  { code: 'ASI05', name: 'Goal Hijacking' },
  { code: 'ASI06', name: 'Data Exfiltration' },
  { code: 'ASI07', name: 'Multi-Agent Hijacking' },
  { code: 'ASI08', name: 'Supply Chain Attack' },
  { code: 'ASI09', name: 'Agent DoS' },
  { code: 'ASI10', name: 'Unbounded Resource Consumption' },
]

// ─── Main component ───────────────────────────────────────────────────────────

export default function DefensesPage({ onBack, onRunAudit, onFindings, onRedTeam, onConsole }: DefensesPageProps) {
  const [inputValue, setInputValue]   = useState('HR Agent')
  const [targetId, setTargetId]       = useState('HR Agent')
  const [coverage, setCoverage]       = useState<Coverage | null>(null)
  const [trends, setTrends]           = useState<TrendEntry[]>([])
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState<string | null>(null)
  const [noData, setNoData]           = useState(false)

  // ── Fetch both endpoints simultaneously ────────────────────────────────────
  const fetchData = useCallback(async (id: string) => {
    const trimmed = id.trim()
    if (!trimmed) return

    setLoading(true)
    setError(null)
    setNoData(false)
    setCoverage(null)
    setTrends([])

    try {
      const [covResult, trendsResult] = await Promise.allSettled([
        getTargetCoverage(trimmed),
        getTargetTrends(trimmed, 30),
      ])

      if (covResult.status === 'rejected') {
        if (covResult.reason instanceof ApiError && covResult.reason.status === 404) {
          setNoData(true)
          return
        }
        throw covResult.reason
      }

      setCoverage(covResult.value as Coverage)
      setTrends(trendsResult.status === 'fulfilled' ? (trendsResult.value as TrendEntry[]) : [])
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Unknown error occurred')
    } finally {
      setLoading(false)
    }
  }, [])

  // Load on mount with default target
  useEffect(() => {
    fetchData('HR Agent')
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleLoad = () => {
    const id = inputValue.trim()
    if (!id) return
    setTargetId(id)
    fetchData(id)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') handleLoad()
  }

  // ── Derived data ───────────────────────────────────────────────────────────

  // Group trends by strategy, sort by date, cap at 14 days
  const trendsByStrategy = trends.reduce<Record<string, TrendEntry[]>>((acc, entry) => {
    if (!acc[entry.strategy]) acc[entry.strategy] = []
    acc[entry.strategy].push(entry)
    return acc
  }, {})

  Object.keys(trendsByStrategy).forEach(strategy => {
    trendsByStrategy[strategy] = [...trendsByStrategy[strategy]]
      .sort((a, b) => a.date.localeCompare(b.date))
      .slice(-14)
  })

  const testedCount   = coverage?.tested_classes.length ?? 0
  const coveragePct   = Math.round((testedCount / 10) * 100)
  const openByClass   = coverage?.open_findings_by_class ?? {}
  const maxOpen       = Math.max(...Object.values(openByClass), 1)

  const getClassState = (code: string): 'vulnerable' | 'tested' | 'untested' => {
    if (!coverage) return 'untested'
    if (coverage.tested_classes.includes(code)) {
      return (openByClass[code] ?? 0) > 0 ? 'vulnerable' : 'tested'
    }
    return 'untested'
  }

  // ─── RENDER ───────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-black text-white font-mono">
      <Navbar onLogoClick={onBack} onRunAudit={onRunAudit} onFindings={onFindings} onRedTeam={onRedTeam} onConsole={onConsole} />

      {/* ── TARGET SELECTOR ── */}
      <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-16 border-b border-white/10 pt-36">
        <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-10">
          // DEFENSES — TARGET COVERAGE
        </p>

        {/* Input row */}
        <div className="flex flex-col sm:flex-row gap-3 mb-8">
          <div className="flex items-center border border-white/20 bg-white/[0.03] flex-1
                          focus-within:border-white/40 transition-colors">
            <span className="px-3 text-white/30 text-xs border-r border-white/10 py-3 shrink-0
                             uppercase tracking-wider">
              Target
            </span>
            <input
              type="text"
              value={inputValue}
              onChange={e => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="e.g. HR Agent"
              className="flex-1 bg-transparent px-3 py-3 text-white text-xs font-mono
                         placeholder:text-white/20 outline-none"
              disabled={loading}
            />
          </div>
          <button
            onClick={handleLoad}
            disabled={loading || !inputValue.trim()}
            className="px-8 py-3 bg-red-600 text-white text-xs uppercase tracking-[0.2em] font-medium
                       hover:bg-red-500 disabled:opacity-30 disabled:cursor-not-allowed
                       transition-all duration-200"
          >
            {loading ? 'Loading...' : 'Load →'}
          </button>
        </div>

        {/* Stats pills — only shown when data is loaded */}
        {coverage && !loading && (
          <div className="flex flex-wrap gap-3">
            {([
              { label: 'Total Findings',    value: String(coverage.total_findings) },
              { label: 'Open',              value: String(coverage.open_findings) },
              { label: 'ASI Classes Tested',value: `${testedCount} / 10` },
              { label: 'Coverage',          value: `${coveragePct}%` },
            ] as const).map(pill => (
              <div
                key={pill.label}
                className="flex items-center gap-3 border border-white/10 bg-white/[0.02] px-4 py-2"
              >
                <span className="text-white/30 text-[10px] uppercase tracking-wider">{pill.label}</span>
                <span className="text-white text-sm font-mono font-medium">{pill.value}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ── LOADING STATE ── */}
      {loading && (
        <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-16 border-b border-white/10">
          <p className="text-white/40 text-xs uppercase tracking-[0.25em] animate-pulse">
            Fetching coverage data...
          </p>
        </section>
      )}

      {/* ── ERROR STATE ── */}
      {error && !loading && (
        <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-10 border-b border-white/10">
          <div className="border border-red-600/40 bg-red-950/10 px-5 py-4">
            <p className="text-red-400 text-[10px] uppercase tracking-wider mb-1.5">Error</p>
            <p className="text-red-300/70 text-[11px] font-mono leading-relaxed">{error}</p>
          </div>
        </section>
      )}

      {/* ── NO DATA STATE ── */}
      {noData && !loading && (
        <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-16 border-b border-white/10">
          <p className="text-white/30 text-xs uppercase tracking-[0.2em]">
            No data for target &lsquo;{targetId}&rsquo;. Run an audit against this target first.
          </p>
        </section>
      )}

      {/* ── MAIN DATA SECTIONS ── */}
      {coverage && !loading && (
        <>
          {/* ── SECTION 01 — ASI COVERAGE MAP ── */}
          <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-16 border-b border-white/10">
            <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-10">
              // SECTION 01 — ASI COVERAGE MAP
            </p>

            {/* Coverage stat line */}
            <div className="flex items-center gap-4 mb-8">
              <span className="text-white text-2xl font-bold font-mono">{testedCount} / 10</span>
              <span className="text-white/30 text-xs uppercase tracking-wider">classes tested</span>
              <div className="flex-1 h-[1px] bg-white/10 ml-2" />
              <span className="text-white/40 text-xs font-mono">{coveragePct}% coverage</span>
            </div>

            {/* 10-cell grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">
              {ASI_CLASSES.map(asi => {
                const state     = getClassState(asi.code)
                const openCount = openByClass[asi.code] ?? 0

                return (
                  <div
                    key={asi.code}
                    className={`border p-4 relative transition-all duration-200 ${
                      state === 'vulnerable'
                        ? 'border-red-600/50 bg-red-950/15'
                        : state === 'tested'
                          ? 'border-white/20 bg-white/[0.04]'
                          : 'border-white/[0.06] bg-transparent opacity-40'
                    }`}
                  >
                    {/* ASI code + state indicator */}
                    <div className="flex items-start justify-between mb-3">
                      <span className="text-[9px] text-red-500/70 uppercase tracking-wider font-mono">
                        {asi.code}
                      </span>

                      {state === 'vulnerable' && (
                        <div className="flex items-center gap-1.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
                          <span className="text-[9px] text-red-400 font-mono font-medium">{openCount}</span>
                        </div>
                      )}

                      {state === 'tested' && (
                        <svg
                          className="w-3.5 h-3.5 text-white/50"
                          viewBox="0 0 12 12"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="1.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        >
                          <polyline points="1.5,6.5 4.5,9.5 10.5,2.5" />
                        </svg>
                      )}

                      {state === 'untested' && (
                        <span className="text-white/25 text-[11px] font-mono">—</span>
                      )}
                    </div>

                    {/* ASI name */}
                    <div className="text-white text-[10px] uppercase tracking-[0.08em] font-medium leading-tight">
                      {asi.name}
                    </div>
                  </div>
                )
              })}
            </div>
          </section>

          {/* ── SECTION 02 — ATTACK TRENDS ── */}
          <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-16 border-b border-white/10">
            <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-10">
              // SECTION 02 — ATTACK TRENDS
            </p>

            {Object.keys(trendsByStrategy).length === 0 ? (
              <p className="text-white/30 text-xs uppercase tracking-[0.15em]">
                No trend data available for this target. Run an audit first.
              </p>
            ) : (
              <div className="flex flex-col gap-12">
                {Object.entries(trendsByStrategy).map(([strategy, entries]) => (
                  <div key={strategy}>
                    {/* Strategy header */}
                    <div className="flex items-center gap-3 mb-5">
                      <span className="text-white text-xs uppercase tracking-[0.15em] shrink-0">
                        {strategy.replace(/_/g, ' ')}
                      </span>
                      <div className="flex-1 h-[1px] bg-white/10" />
                      <span className="text-white/30 text-[10px] font-mono shrink-0">
                        {entries.length} day{entries.length !== 1 ? 's' : ''}
                      </span>
                    </div>

                    {/* Mini bar chart */}
                    <div className="relative overflow-visible">
                      <div className="flex items-end gap-1 h-16 border-b border-white/10 pb-0.5">
                        {entries.map(entry => {
                          const pct         = Math.max(entry.success_rate * 100, 2)
                          const isHigh      = entry.success_rate > 0.5
                          const tooltipText = `${entry.date}: ${entry.successes}/${entry.attempts} (${(entry.success_rate * 100).toFixed(0)}%)`

                          return (
                            <div
                              key={entry.date}
                              className="relative group flex-1 flex flex-col justify-end"
                              style={{ height: '100%' }}
                            >
                              {/* Hover tooltip */}
                              <div
                                className="absolute bottom-full mb-2 left-1/2 -translate-x-1/2 z-20
                                           pointer-events-none select-none
                                           opacity-0 group-hover:opacity-100 transition-opacity duration-150
                                           whitespace-nowrap border border-white/20 bg-black px-2 py-1"
                              >
                                <span className="text-white/70 text-[9px] font-mono">{tooltipText}</span>
                              </div>

                              {/* Bar */}
                              <div
                                className={`w-full transition-all duration-500 ${
                                  isHigh ? 'bg-red-600' : 'bg-white/20'
                                }`}
                                style={{ height: `${pct}%` }}
                              />
                            </div>
                          )
                        })}
                      </div>

                      {/* Date range labels */}
                      <div className="flex justify-between mt-1.5">
                        <span className="text-white/25 text-[9px] font-mono">{entries[0]?.date}</span>
                        <span className="text-white/25 text-[9px] font-mono">{entries[entries.length - 1]?.date}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* ── SECTION 03 — OPEN FINDINGS SUMMARY ── */}
          <section className="px-6 sm:px-10 md:px-16 lg:px-20 py-16">
            <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-10">
              // SECTION 03 — OPEN FINDINGS SUMMARY
            </p>

            {Object.keys(openByClass).length === 0 ? (
              <p className="text-white/30 text-xs uppercase tracking-[0.15em]">
                No open findings for this target.
              </p>
            ) : (
              <div className="flex flex-col gap-5 max-w-2xl">
                {Object.entries(openByClass)
                  .sort(([, a], [, b]) => b - a)
                  .map(([code, count]) => {
                    const asi      = ASI_CLASSES.find(a => a.code === code)
                    const barWidth = Math.round((count / maxOpen) * 100)

                    return (
                      <div key={code}>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-3">
                            <span className="text-red-500/70 text-[10px] font-mono uppercase tracking-wider w-12">
                              {code}
                            </span>
                            <span className="text-white/60 text-[10px] uppercase tracking-[0.08em]">
                              {asi?.name ?? code}
                            </span>
                          </div>
                          <span className="text-white/50 text-xs font-mono font-medium ml-4">
                            {count}
                          </span>
                        </div>
                        <div className="h-[3px] bg-white/[0.06] w-full">
                          <div
                            className="h-full bg-red-600/40 transition-all duration-700"
                            style={{ width: `${barWidth}%` }}
                          />
                        </div>
                      </div>
                    )
                  })}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  )
}
