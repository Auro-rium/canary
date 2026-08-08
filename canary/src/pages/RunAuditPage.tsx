import { useState, useEffect, useRef, useCallback } from 'react'
import Navbar from '../components/Navbar'
import AgentGraphPanel from '../components/AgentGraphPanel'
import { getRunReportMarkdown, runCampaignSSE } from '../lib/api'
import { TECHNIQUES } from '../lib/techniques'
import type { Phase, AgentStatus, LogEntry, FindingPayload, CompletePayload } from '../lib/types'

// ─── Types ────────────────────────────────────────────────────────────────────

interface AgentDef {
  id: string
  label: string
  role: 'control' | 'attacker' | 'evaluator' | 'target' | 'store'
  x: number
  y: number
}
// Exported (not just const) so the canonical topology data stays defined here even though
// the SVG view uses its own independent layout constants.
export const AGENTS: AgentDef[] = [
  { id: 'orchestrator', label: 'Orchestrator',  role: 'control',   x: 0.5,  y: 0.12 },
  { id: 'strategist',   label: 'Strategist',    role: 'control',   x: 0.2,  y: 0.12 },
  { id: 'attacker',     label: 'Attk. Agent',   role: 'attacker',  x: 0.2,  y: 0.38 },
  { id: 'evaluator',    label: 'Eval. Agent',   role: 'evaluator', x: 0.5,  y: 0.38 },
  { id: 'target',       label: 'Target',         role: 'target',    x: 0.5,  y: 0.68 },
  { id: 'reporter',     label: 'Reporter',       role: 'store',     x: 0.8,  y: 0.68 },
  { id: 'findings',     label: 'Findings Store', role: 'store',     x: 0.5,  y: 0.88 },
]

export const EDGES = [
  { from: 'orchestrator', to: 'attacker' },
  { from: 'orchestrator', to: 'evaluator' },
  { from: 'orchestrator', to: 'strategist' },
  { from: 'strategist',   to: 'attacker' },
  { from: 'attacker',     to: 'target' },
  { from: 'evaluator',    to: 'target' },
  { from: 'evaluator',    to: 'findings' },
  { from: 'evaluator',    to: 'reporter' },
  { from: 'reporter',     to: 'findings' },
]

// ─── Main component ───────────────────────────────────────────────────────────

interface RunAuditPageProps {
  onBack: () => void
}

const makeCampaignId = () => `RX-${Math.floor(Math.random() * 900000 + 100000)}`

export default function RunAuditPage({ onBack }: RunAuditPageProps) {
  const [phase, setPhase] = useState<Phase>('idle')
  const [targetUrl, setTargetUrl] = useState('')
  const [showAdvancedTarget, setShowAdvancedTarget] = useState(false)
  const [targetHeaders, setTargetHeaders] = useState('')
  const [targetRequestTemplate, setTargetRequestTemplate] = useState('')
  const [targetResponsePath, setTargetResponsePath] = useState('')
  const [selectedTechniques, setSelectedTechniques] = useState<string[]>([])
  const [campaignId, setCampaignId] = useState(makeCampaignId)
  const [agentStatuses, setAgentStatuses] = useState<Record<string, AgentStatus>>({})
  const [activeEdge, setActiveEdge] = useState<string | null>(null)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [report, setReport] = useState<CompletePayload | null>(null)
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null)
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())
  const [elapsedSeconds, setElapsedSeconds] = useState(0)

  const logEndRef  = useRef<HTMLDivElement>(null)
  const startTimeRef = useRef<number>(0)

  // Refs for canvas loop (avoids re-creating the loop on every state change)
  const phaseRef         = useRef<Phase>('idle')
  const statusesRef      = useRef<Record<string, AgentStatus>>({})
  const activeEdgesRef   = useRef<Set<string>>(new Set())

  useEffect(() => { phaseRef.current = phase }, [phase])
  useEffect(() => { statusesRef.current = agentStatuses }, [agentStatuses])

  // Fetch the full LLM-generated markdown report once the run completes.
  useEffect(() => {
    if (!report) return
    let cancelled = false
    ;(async () => {
      try {
        const data = await getRunReportMarkdown(report.run_id)
        if (!cancelled) setReportMarkdown(data.markdown)
      } catch {
        // report.md may not exist for older runs — leave as null
      }
    })()
    return () => { cancelled = true }
  }, [report])

  // Sync active edge into the Set ref
  useEffect(() => {
    if (activeEdge) {
      activeEdgesRef.current.add(activeEdge)
      const t = setTimeout(() => {
        activeEdgesRef.current.delete(activeEdge)
        setActiveEdge(null)
      }, 1200)
      return () => clearTimeout(t)
    }
  }, [activeEdge])

  // Elapsed campaign timer (drives the Phase 02 config-summary clock)
  useEffect(() => {
    if (phase === 'running') {
      startTimeRef.current = Date.now()
      setElapsedSeconds(0)
      const interval = setInterval(() => {
        setElapsedSeconds(Math.floor((Date.now() - startTimeRef.current) / 1000))
      }, 1000)
      return () => clearInterval(interval)
    }
  }, [phase])

  // Auto-scroll log
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const appendLog = useCallback((level: LogEntry['level'], message: string) => {
    const timestamp = new Date().toISOString().slice(11, 19)
    setLogs(prev => [...prev, { timestamp, level, message }])
  }, [])

  const updateAgent = useCallback((id: string, status: AgentStatus) => {
    setAgentStatuses(prev => ({ ...prev, [id]: status }))
  }, [])

  const fireEdge = useCallback((key: string) => {
    setActiveEdge(key)
  }, [])

  const toggleTechnique = (id: string) => {
    setSelectedTechniques(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    )
  }

  // ── SSE event dispatcher (real backend) ────────────────────────────────────
  const handleSSEEvent = useCallback((event: { type: string; payload: unknown }) => {
    if (event.type === 'agent_state') {
      const p = event.payload as { agent_id: string; status: AgentStatus; active_edge?: string }
      updateAgent(p.agent_id, p.status)
      if (p.active_edge) fireEdge(p.active_edge)
    }
    if (event.type === 'log') {
      const p = event.payload as { level: LogEntry['level']; message: string }
      appendLog(p.level, p.message)
    }
    if (event.type === 'finding') {
      appendLog('FINDING', (() => {
        const f = event.payload as FindingPayload
        return `${f.severity}: ${f.asi_code} — ${f.verdict}`
      })())
    }
    if (event.type === 'campaign_complete') {
      setReport(event.payload as CompletePayload)
      setPhase('complete')
    }
    if (event.type === 'campaign_failed') {
      const p = event.payload as { message?: string }
      appendLog('ERROR', p.message || 'Real agent pipeline failed. No report was generated.')
      setPhase('failed')
    }
  }, [appendLog, updateAgent, fireEdge])

  // ── Real backend via SSE ────────────────────────────────────────────────────
  const runRealCampaign = useCallback(async (activeCampaignId: string) => {
    // Optional fields are forwarded only when explicitly configured.
    let parsedHeaders: Record<string, string> = {}
    if (targetHeaders.trim()) {
      try {
        parsedHeaders = JSON.parse(targetHeaders)
      } catch {
        appendLog('ERROR', 'Custom headers must be valid JSON — ignoring.')
      }
    }
    // Backend was reached and explicitly rejected the request (bad auth,
    // target not allowlisted, concurrency cap hit, etc.) — this is a real,
    // actionable answer, not a "server is down" case. Surface it as-is
    // rather than hiding an explicit backend rejection.
    await runCampaignSSE(
      {
        campaign_id: activeCampaignId,
        target_url: targetUrl.trim(),
        techniques: selectedTechniques,
        headers: parsedHeaders,
        request_template: targetRequestTemplate.trim() || undefined,
        response_path: targetResponsePath.trim() || undefined,
      },
      handleSSEEvent,
    )
  }, [targetUrl, targetHeaders, targetRequestTemplate, targetResponsePath, selectedTechniques, handleSSEEvent, appendLog])

  // ── Entry point ─────────────────────────────────────────────────────────────
  const startCampaign = useCallback(() => {
    if (!targetUrl.trim()) {
      appendLog('ERROR', 'An HTTP target endpoint is required before starting a campaign.')
      return
    }
    if (!selectedTechniques.length) return

    const nextCampaignId = makeCampaignId()
    setCampaignId(nextCampaignId)
    setPhase('running')
    setLogs([])
    setReport(null)
    setReportMarkdown(null)
    setAgentStatuses({})
    activeEdgesRef.current.clear()

    runRealCampaign(nextCampaignId).catch((err: Error & { status?: number }) => {
      appendLog('ERROR', err.status !== undefined
        ? err.message
        : `Backend unavailable (${err.message}). No report was generated.`)
      setPhase('idle')
    })
  }, [targetUrl, selectedTechniques.length, runRealCampaign, appendLog])

  const exportJSON = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href = url; a.download = `${report.campaign_id}.json`; a.click()
    URL.revokeObjectURL(url)
  }

  const resetCampaign = () => {
    setPhase('idle')
    setReport(null)
    setLogs([])
    setAgentStatuses({})
    setSelectedTechniques([])
    activeEdgesRef.current.clear()
  }

  // ─── VISUAL HELPERS ─────────────────────────────────────────────
  const levelBadgeClass = (level: LogEntry['level']) => {
    if (level === 'ATTACK')  return 'bg-red-600/80 text-white'
    if (level === 'EVAL')    return 'bg-blue-600/70 text-white'
    if (level === 'FINDING') return 'border border-red-500/60 text-red-400'
    if (level === 'ERROR')   return 'bg-red-900 text-red-300'
    return 'text-white/25'
  }

  const severityBar = (severity: string) => {
    const bars = severity === 'CRITICAL' ? 4 : severity === 'HIGH' ? 3 : severity === 'MEDIUM' ? 2 : 1
    const colorClass =
      severity === 'CRITICAL' ? 'text-red-500' :
      severity === 'HIGH'     ? 'text-orange-400' :
      severity === 'MEDIUM'   ? 'text-yellow-400' : 'text-white/30'
    return { filled: '█'.repeat(bars), empty: '░'.repeat(4 - bars), colorClass }
  }

  const scoreBlocks = (score: number) => {
    const filled = Math.round(score * 10)
    return `[${'█'.repeat(filled)}${'░'.repeat(10 - filled)}] ${(score * 100).toFixed(0)}%`
  }

  const verdictPillClass = (verdict: FindingPayload['verdict']) => {
    if (verdict === 'VULNERABLE') return 'bg-red-600 text-white px-3 py-0.5 rounded-full text-[9px] font-bold uppercase tracking-wider'
    if (verdict === 'RESILIENT')  return 'border border-white/60 text-white/70 px-3 py-0.5 rounded-full text-[9px] uppercase tracking-wider'
    return 'border border-yellow-400/60 text-yellow-400 px-3 py-0.5 rounded-full text-[9px] uppercase tracking-wider'
  }

  const severityBorderColor = (severity: FindingPayload['severity']) => {
    if (severity === 'CRITICAL') return '#dc2626'
    if (severity === 'HIGH')     return '#f97316'
    if (severity === 'MEDIUM')   return '#eab308'
    return 'rgba(255,255,255,0.2)'
  }

  const formatElapsed = (s: number) =>
    `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`

  const toggleFindingExpanded = (id: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const copySummary = () => {
    if (!report) return
    const text = [
      `Campaign: ${report.campaign_id}`,
      `Target: ${targetUrl.trim() || 'N/A'}`,
      `Critical: ${report.critical_count}`,
      `High: ${report.high_count}`,
      `Total Findings: ${report.total_findings}`,
      `Duration: ${report.duration_seconds}s`,
      '',
      'Findings:',
      ...report.findings.map(f => `  [${f.severity}] ${f.asi_code} ${f.technique_id}: ${f.verdict} (${(f.score * 100).toFixed(0)}%)`),
    ].join('\n')
    navigator.clipboard?.writeText(text)
  }

  const isRunning = phase === 'running'

  // ─── RENDER ──────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-black text-white font-mono">
      <Navbar onRunAudit={resetCampaign} onLogoClick={onBack} />

      {/* ── PHASE 01: CAMPAIGN CONFIGURATION ── */}
      <section
        className="px-6 sm:px-10 md:px-16 lg:px-20 py-16 border-b border-white/10 pt-36"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)',
          backgroundSize: '28px 28px',
        }}
      >
        <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase mb-10">
          // PHASE 01 — CAMPAIGN CONFIGURATION
        </p>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">

          {/* LEFT: Target config */}
          <div>
            {/* Campaign ID + status */}
            <div className="flex items-center gap-3 border border-white/15 bg-white/[0.03] px-4 py-3 mb-8">
              <div className="flex flex-col gap-0.5 flex-1 min-w-0">
                <span className="text-white/30 text-[9px] uppercase tracking-[0.25em]">Campaign ID</span>
                <span className="text-white text-base font-mono font-bold tracking-wider truncate">{campaignId}</span>
              </div>
              <div
                className={`text-[9px] uppercase tracking-wider px-2 py-1 font-mono border shrink-0 ${
                  isRunning ? 'border-red-500/40 text-red-400 bg-red-950/20' : 'border-white/15 text-white/30'
                }`}
              >
                {isRunning ? '● RUNNING' : 'READY'}
              </div>
            </div>

            <p className="text-white text-xs uppercase tracking-[0.2em] mb-6">Target</p>

            {/* URL input */}
            <div className="flex flex-col gap-2 mb-6">
              <label className="text-white/40 text-[10px] uppercase tracking-wider">Target Endpoint</label>
              <div className="flex items-center border border-white/20 bg-white/[0.03] focus-within:border-white/40 transition-colors">
                <span className="px-3 text-white/30 text-xs border-r border-white/10 py-3 shrink-0">URL</span>
                <input
                  type="text"
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  placeholder="https://your-agent-endpoint.com/v1/chat"
                  className="flex-1 bg-transparent px-3 py-3 text-white text-xs font-mono placeholder:text-white/20 outline-none"
                  disabled={isRunning}
                />
              </div>
              <p className="text-white/20 text-[9px] uppercase tracking-wider mt-1">
                HTTP/JSON REST only — custom headers &amp; request/response schema supported below
              </p>
            </div>

            {/* Advanced target config — opt-in, leave blank for the configured HTTP request contract */}
            <div className="mb-6">
              <button
                type="button"
                onClick={() => setShowAdvancedTarget(v => !v)}
                disabled={isRunning}
                className="text-[9px] uppercase tracking-wider text-white/40 hover:text-white/70 border border-white/15 hover:border-white/30 px-3 py-1.5 transition-colors disabled:opacity-30"
              >
                {showAdvancedTarget ? '− Hide' : '+ Advanced'} target config
              </button>

              {showAdvancedTarget && (
                <div className="flex flex-col gap-4 mt-4">
                  <div className="flex flex-col gap-2">
                    <label className="text-white/40 text-[10px] uppercase tracking-wider">
                      Headers (JSON)
                    </label>
                    <textarea
                      value={targetHeaders}
                      onChange={e => setTargetHeaders(e.target.value)}
                      placeholder={'{"Authorization": "Bearer sk-...", "X-API-Key": "..."}'}
                      rows={2}
                      className="bg-white/[0.03] border border-white/20 focus:border-white/40 transition-colors px-3 py-2 text-white text-xs font-mono placeholder:text-white/20 outline-none resize-none"
                      disabled={isRunning}
                    />
                  </div>

                  <div className="flex flex-col gap-2">
                    <label className="text-white/40 text-[10px] uppercase tracking-wider">
                      Request Template (JSON, use {'"{{PROMPT}}"'} as the payload placeholder)
                    </label>
                    <textarea
                      value={targetRequestTemplate}
                      onChange={e => setTargetRequestTemplate(e.target.value)}
                      placeholder={'{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}'}
                      rows={2}
                      className="bg-white/[0.03] border border-white/20 focus:border-white/40 transition-colors px-3 py-2 text-white text-xs font-mono placeholder:text-white/20 outline-none resize-none"
                      disabled={isRunning}
                    />
                  </div>

                  <div className="flex flex-col gap-2">
                    <label className="text-white/40 text-[10px] uppercase tracking-wider">
                      Response Path (dot-path into the JSON response)
                    </label>
                    <input
                      type="text"
                      value={targetResponsePath}
                      onChange={e => setTargetResponsePath(e.target.value)}
                      placeholder="choices.0.message.content"
                      className="bg-white/[0.03] border border-white/20 focus:border-white/40 transition-colors px-3 py-2 text-white text-xs font-mono placeholder:text-white/20 outline-none"
                      disabled={isRunning}
                    />
                  </div>

                  <p className="text-white/20 text-[9px] uppercase tracking-wider">
                    Leave all three blank to use the default {'{"message": ...} → {"response": ...}'} contract
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* RIGHT: Technique selection */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <p className="text-white text-xs uppercase tracking-[0.2em]">Attack Techniques</p>
              <button
                onClick={() => setSelectedTechniques(TECHNIQUES.map(t => t.id))}
                disabled={isRunning}
                className="text-[9px] uppercase tracking-wider text-white/40 hover:text-white/70 border border-white/15 hover:border-white/30 px-3 py-1.5 transition-colors disabled:opacity-30"
              >
                Select All
              </button>
            </div>
            <p className="text-white/30 text-[10px] mb-6">Select techniques to include in the red-team run.</p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {TECHNIQUES.map(tech => {
                const selected = selectedTechniques.includes(tech.id)
                const { filled, empty, colorClass } = severityBar(tech.severity)
                return (
                  <div
                    key={tech.id}
                    onClick={() => !isRunning && toggleTechnique(tech.id)}
                    className={`relative overflow-hidden border p-4 transition-all duration-200 ${
                      isRunning ? 'cursor-not-allowed opacity-60' : 'cursor-pointer'
                    } ${
                      selected
                        ? 'border-l-2 border-l-red-500 border-red-600/50 bg-red-950/20'
                        : 'border-white/10 bg-white/[0.02] hover:border-white/25'
                    }`}
                  >
                    {selected && (
                      <div className="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-red-500/60 to-transparent" />
                    )}
                    <div className="flex items-start justify-between mb-3">
                      <span className="text-[10px] text-red-500/70 uppercase tracking-wider font-mono">{tech.asiCode}</span>
                      {selected && (
                        <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse-red" />
                      )}
                    </div>
                    <div className="text-white text-xs uppercase tracking-[0.1em] font-medium mb-1">{tech.name}</div>
                    <div className="text-white/40 text-[10px] leading-relaxed mb-3">{tech.description}</div>
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-[10px] ${colorClass}`}>
                        {filled}<span className="text-white/15">{empty}</span>
                      </span>
                      <span className={`text-[9px] uppercase tracking-wider ${colorClass}`}>{tech.severity}</span>
                      <span className="text-white/20 text-[9px] ml-auto">{tech.estimatedDuration}</span>
                    </div>
                  </div>
                )
              })}
            </div>

            <div className="mt-6 flex items-center justify-between">
              <span className="text-white/30 text-[10px] uppercase tracking-wider">
                {selectedTechniques.length} technique{selectedTechniques.length !== 1 ? 's' : ''} selected
              </span>
            </div>

            <button
              disabled={selectedTechniques.length === 0 || isRunning}
              onClick={startCampaign}
              className="w-full mt-3 py-4 bg-red-600 text-white text-xs uppercase tracking-[0.2em] font-medium
                         hover:bg-red-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors duration-200"
              style={{
                backgroundImage: 'linear-gradient(90deg, rgba(255,255,255,0.08) 0%, rgba(255,255,255,0.08) 100%)',
                backgroundSize: isRunning ? '100% 100%' : '0% 100%',
                backgroundRepeat: 'no-repeat',
                transition: 'background-size 1s ease, background-color 0.2s ease',
              }}
            >
              {isRunning ? '// EXECUTING...' : '// RUN AUDIT →'}
            </button>
          </div>
        </div>
      </section>

      {/* ── PHASE 02: EXECUTION THEATER ── */}
      <section className="border-b border-white/10">
        <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase px-6 sm:px-10 md:px-16 lg:px-20 pt-10 pb-6">
          // PHASE 02 — EXECUTION THEATER
        </p>

        <div className="flex flex-col lg:flex-row border-t border-white/10" style={{ minHeight: 560 }}>

          {/* Config summary */}
          {phase !== 'idle' && (
            <div className="lg:w-[200px] shrink-0 border-b lg:border-b-0 lg:border-r border-white/10 p-5 flex flex-col gap-4 bg-white/[0.01]">
              <div>
                <div className="text-white/25 text-[9px] uppercase tracking-[0.2em] mb-1">Campaign</div>
                <div className="text-white font-mono font-bold text-sm tracking-wider">{campaignId}</div>
              </div>
              <div>
                <div className="text-white/25 text-[9px] uppercase tracking-[0.2em] mb-1">Target</div>
                <div className="text-white/60 font-mono text-[10px] break-all leading-relaxed">
                  {targetUrl.trim() || 'No HTTP target configured'}
                </div>
              </div>
              <div>
                <div className="text-white/25 text-[9px] uppercase tracking-[0.2em] mb-1">Techniques</div>
                <div className="text-white/60 font-mono text-[10px]">{selectedTechniques.length} selected</div>
              </div>
              <div>
                <div className="text-white/25 text-[9px] uppercase tracking-[0.2em] mb-1">Status</div>
                <div className={`flex items-center gap-1.5 font-mono text-[10px] ${isRunning ? 'text-red-400' : 'text-white/40'}`}>
                  {phase === 'running' ? 'RUNNING' : phase === 'complete' ? 'COMPLETE' : phase === 'failed' ? 'FAILED' : 'IDLE'}
                  {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse-red shrink-0" />}
                </div>
              </div>
              <div>
                <div className="text-white/25 text-[9px] uppercase tracking-[0.2em] mb-1">Elapsed</div>
                <div className="text-white/60 font-mono text-[11px]">{formatElapsed(elapsedSeconds)}</div>
              </div>
            </div>
          )}

          {/* SVG Topology */}
          <div className="flex-1 relative min-h-[500px] flex items-center justify-center">
            <AgentGraphPanel phase={phase} statuses={agentStatuses} activeEdge={activeEdge} />
          </div>

          {/* Log stream */}
          <div className="lg:w-[300px] shrink-0 border-t lg:border-t-0 lg:border-l border-white/10 flex flex-col">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 shrink-0">
              <span className="text-white/40 text-[10px] uppercase tracking-wider">Live Output</span>
              <div className="flex items-center gap-2">
                <span className="text-white/25 text-[9px]">[{logs.length}]</span>
                {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse-red" />}
                <span className="text-white/30 text-[10px]">{isRunning ? 'LIVE' : phase === 'complete' ? 'DONE' : phase === 'failed' ? 'FAILED' : 'IDLE'}</span>
              </div>
            </div>

            <div className="overflow-y-auto flex-1 max-h-[500px]">
              {logs.length === 0 && (
                <div className="px-4 py-8 text-center text-white/15 text-[10px] uppercase tracking-[0.25em]">
                  No output yet
                </div>
              )}
              {logs.map((entry, i) => (
                <div key={i} className="px-3 py-1.5 border-b border-white/[0.04] flex gap-2 items-start">
                  <span className="text-white/15 text-[9px] font-mono shrink-0 w-5 text-right mt-0.5">{i + 1}</span>
                  <span className="text-white/25 text-[9px] font-mono shrink-0 mt-0.5">{entry.timestamp}</span>
                  <span className={`text-[8px] uppercase tracking-wider shrink-0 mt-0.5 px-1 py-0.5 ${levelBadgeClass(entry.level)}`}>
                    {entry.level}
                  </span>
                  <span className="text-white/70 text-[10px] font-mono leading-relaxed">{entry.message}</span>
                </div>
              ))}
              {isRunning && (
                <div className="px-4 py-2">
                  <span className="text-red-500 animate-blink text-[10px]">█</span>
                </div>
              )}
              <div ref={logEndRef} />
            </div>
          </div>
        </div>
      </section>

      {/* ── PHASE 03: FINDINGS REPORT ── */}
      {phase === 'complete' && report && (
        <section className="animate-report">
          <p className="text-white/30 text-[10px] tracking-[0.3em] uppercase px-6 sm:px-10 md:px-16 lg:px-20 pt-10 pb-0">
            // PHASE 03 — FINDINGS REPORT
          </p>

          {/* Summary bar */}
          <div className="bg-gradient-to-r from-red-950/80 to-black px-6 sm:px-10 md:px-16 lg:px-20 py-4 mt-6 border-y border-red-900/30">
            <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
              <span className="text-white font-bold tracking-wider">CAMPAIGN {report.campaign_id}</span>
              <span className="text-red-900">│</span>
              <span className="text-red-400">CRITICAL: {report.critical_count}</span>
              <span className="text-red-900">│</span>
              <span className="text-orange-400">HIGH: {report.high_count}</span>
              <span className="text-red-900">│</span>
              <span className="text-white/60">TOTAL FINDINGS: {report.total_findings}</span>
              <span className="text-red-900">│</span>
              <span className="text-white/60">DURATION: {report.duration_seconds}s</span>
              <span className="text-red-900">│</span>
              <span className="text-white/60">TARGET: {targetUrl.trim() || 'No HTTP target configured'}</span>
            </div>
          </div>

          {/* Risk severity overview */}
          {(() => {
            const vulnFindings = report.findings.filter(f => f.verdict === 'VULNERABLE')
            const critCount = vulnFindings.filter(f => f.severity === 'CRITICAL').length
            const highCount = vulnFindings.filter(f => f.severity === 'HIGH').length
            const medCount  = vulnFindings.filter(f => f.severity === 'MEDIUM').length
            const lowCount  = vulnFindings.filter(f => f.severity === 'LOW').length
            if (critCount + highCount + medCount + lowCount === 0) return null
            return (
              <div className="px-6 sm:px-10 md:px-16 lg:px-20 py-5 border-b border-white/10">
                <div className="text-white/25 text-[9px] uppercase tracking-[0.2em] mb-3">Risk Severity Profile</div>
                <div className="flex h-2 gap-0.5 max-w-[420px]">
                  {critCount > 0 && <div className="bg-red-600" style={{ flex: critCount }} />}
                  {highCount > 0 && <div className="bg-orange-500" style={{ flex: highCount }} />}
                  {medCount  > 0 && <div className="bg-yellow-500" style={{ flex: medCount }} />}
                  {lowCount  > 0 && <div className="bg-white/30" style={{ flex: lowCount }} />}
                </div>
                <div className="flex gap-4 mt-2 flex-wrap">
                  {critCount > 0 && <span className="text-red-500 text-[9px] font-mono">CRITICAL █ {critCount}</span>}
                  {highCount > 0 && <span className="text-orange-400 text-[9px] font-mono">HIGH █ {highCount}</span>}
                  {medCount  > 0 && <span className="text-yellow-400 text-[9px] font-mono">MEDIUM █ {medCount}</span>}
                  {lowCount  > 0 && <span className="text-white/30 text-[9px] font-mono">LOW █ {lowCount}</span>}
                </div>
              </div>
            )
          })()}

          {/* Full narrative report (markdown) */}
          {reportMarkdown && (
            <div className="px-6 sm:px-10 md:px-16 lg:px-20 py-5 border-b border-white/10">
              <div className="text-white/25 text-[9px] uppercase tracking-[0.2em] mb-3">Full Report (Markdown)</div>
              <div className="border border-white/10 bg-white/[0.02] p-4 max-h-96 overflow-y-auto">
                <pre className="text-white/50 text-[10px] leading-relaxed whitespace-pre-wrap font-mono">{reportMarkdown}</pre>
              </div>
            </div>
          )}

          {/* Finding cards */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 px-6 sm:px-10 md:px-16 lg:px-20 py-8">
            {report.findings.map((finding, index) => {
              const isExpanded = expandedFindings.has(finding.finding_id)
              const advInput = finding.adversarial_input
              const needsExpand = advInput.length > 80
              const technique = TECHNIQUES.find(t => t.id === finding.technique_id)

              return (
                <div
                  key={finding.finding_id}
                  className="border border-white/10 bg-white/[0.02] relative animate-report"
                  style={{
                    animationDelay: `${index * 100}ms`,
                    borderLeft: `4px solid ${severityBorderColor(finding.severity)}`,
                  }}
                >
                  {/* Top section */}
                  <div className="p-5 border-b border-white/[0.06]">
                    <div className="flex items-start justify-between gap-3 mb-3">
                      <div className="min-w-0">
                        <div className="text-white/25 text-[10px] font-mono mb-0.5">{finding.asi_code}</div>
                        <div className="text-white font-semibold text-xs uppercase tracking-[0.1em]">
                          {technique?.name ?? finding.technique_id.replace(/-/g, ' ')}
                        </div>
                      </div>
                      <span className={verdictPillClass(finding.verdict)}>{finding.verdict}</span>
                    </div>

                    <div>
                      <div className="text-white/25 text-[9px] uppercase tracking-wider mb-1">Vulnerability Score</div>
                      <div className={`font-mono text-[11px] ${
                        finding.score > 0.7 ? 'text-red-400' : finding.score > 0.4 ? 'text-orange-400' : 'text-white/40'
                      }`}>
                        {scoreBlocks(finding.score)}
                      </div>
                    </div>
                  </div>

                  {/* Adversarial input */}
                  <div className="p-5 border-b border-white/[0.06]">
                    <div className="text-white/20 text-[9px] uppercase tracking-wider mb-2">Adversarial Input</div>
                    <div className="bg-black border border-white/[0.06] p-3">
                      <span className="text-white/60 text-[10px] font-mono leading-relaxed">
                        {isExpanded || !needsExpand ? advInput : `${advInput.slice(0, 80)}...`}
                      </span>
                      {needsExpand && (
                        <button
                          onClick={() => toggleFindingExpanded(finding.finding_id)}
                          className="block mt-1 text-[9px] text-white/30 hover:text-white/60 font-mono underline transition-colors"
                        >
                          [{isExpanded ? 'collapse' : 'expand'}]
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Target response + deterministic hits */}
                  <div className="p-5 border-b border-white/[0.06]">
                    <div className="text-white/20 text-[9px] uppercase tracking-wider mb-1">Target Response</div>
                    <div className="text-white/50 text-[10px] leading-relaxed mb-3">{finding.target_response_summary}</div>
                    {finding.deterministic_hits.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {finding.deterministic_hits.map(hit => (
                          <span key={hit} className="text-[9px] bg-red-950/30 border border-red-600/20 text-red-400/70 px-2 py-0.5 font-mono">
                            {hit}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Recommendation */}
                  <div className="p-5 border-b border-white/[0.06]">
                    <div className="text-white/20 text-[9px] uppercase tracking-wider mb-2">Recommendation</div>
                    <div className="text-white/50 text-[10px] leading-relaxed italic">{finding.recommendation}</div>
                  </div>

                  {/* Footer */}
                  <div className="px-5 py-3 flex items-center justify-between gap-2 flex-wrap">
                    <span className="text-white/15 text-[9px] font-mono">{finding.finding_id}</span>
                    <div className="flex gap-4">
                      <span className="text-white/25 text-[9px] font-mono">path: {finding.verdict_path}</span>
                      <span className="text-white/25 text-[9px] font-mono">threshold: {finding.threshold_used}</span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Report footer */}
          <div className="px-6 sm:px-10 md:px-16 lg:px-20 py-8 border-t border-white/10 flex flex-col sm:flex-row gap-4 sm:items-center sm:justify-between">
            <div className="text-white/20 text-[10px] uppercase tracking-wider">
              Agent Canary · Campaign {report.campaign_id} · {new Date().toISOString().slice(0, 10)}
            </div>
            <div className="flex gap-3 flex-wrap">
              <button
                onClick={copySummary}
                className="px-5 py-2.5 border border-white/20 text-white/60 text-[10px] uppercase tracking-[0.15em] hover:border-white/40 hover:text-white transition-all duration-200"
              >
                Copy Summary
              </button>
              <button
                onClick={exportJSON}
                className="px-5 py-2.5 border border-white/20 text-white/60 text-[10px] uppercase tracking-[0.15em] hover:border-white/40 hover:text-white transition-all duration-200"
              >
                Export JSON
              </button>
              <button
                onClick={resetCampaign}
                className="px-5 py-2.5 bg-red-600 text-white text-[10px] uppercase tracking-[0.15em] hover:bg-red-500 transition-all duration-200"
              >
                New Campaign
              </button>
            </div>
          </div>
        </section>
      )}
    </div>
  )
}
