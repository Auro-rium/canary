import { useEffect, useState } from 'react'
import { ApiError, getConversation } from '../lib/api'
import { can, PERMISSION, useMe } from '../lib/useMe'
import { formatDuration, SEVERITY_STYLE, strategyLabel, VERDICT_STYLE } from '../lib/presentation'
import type { LiveCell } from '../lib/liveState'
import type { ConversationDetail } from '../lib/v2'
import { Badge, ErrorNotice } from './Console'

/** Chat transcript for one conversation, turn by turn, with monitor hits and the first failing turn highlighted. */
export function Transcript({ cell, highlightTurn }: { cell: LiveCell; highlightTurn?: number | null }) {
  const [detail, setDetail] = useState<ConversationDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const id = cell.conversation_id
  const { me } = useMe()
  const canRaw = can(me, PERMISSION.evidenceReadRaw)
  // Redacted by default; raw is opt-in per conversation and never persisted across selections.
  const [wantRaw, setWantRaw] = useState(false)
  const [rawDenied, setRawDenied] = useState(false)
  useEffect(() => { setWantRaw(false); setRawDenied(false) }, [id])
  // Refetch whenever the conversation advances or finishes.
  const version = `${cell.turns}:${cell.status}:${cell.verdict ?? ''}`

  useEffect(() => {
    let live = true
    getConversation(id, wantRaw)
      .then(result => { if (live) { setDetail(result); setError(null) } })
      .catch(e => {
        if (!live) return
        if (wantRaw && e instanceof ApiError && e.status === 403) { setWantRaw(false); setRawDenied(true) } else setError((e as Error).message)
      })
    return () => { live = false }
  }, [id, version, wantRaw])

  const verdict = detail?.verdict ?? null
  const failingTurn = highlightTurn ?? verdict?.first_failing_turn ?? null
  const turns = detail?.conversation.turns ?? []

  return (
    <section data-testid="transcript" aria-label="Conversation transcript" className="border border-white/10 bg-white/[0.02]">
      <header className="flex flex-wrap items-center gap-3 border-b border-white/10 px-4 py-3 text-[10px] uppercase tracking-wider">
        <span className="text-white">{strategyLabel(cell.technique)} · trial {cell.trial_index + 1}</span>
        <Badge>{cell.status.replace(/_/g, ' ')}</Badge>
        {verdict && <span className={VERDICT_STYLE[verdict.verdict]}>{verdict.verdict}</span>}
        {verdict && <Badge className={SEVERITY_STYLE[verdict.severity]}>{verdict.severity} · {verdict.asi_class}</Badge>}
      </header>
      <div className="flex flex-wrap items-center gap-3 border-b border-white/10 px-4 py-2 text-[10px]">
        {detail?.raw
          ? <span data-testid="raw-banner" role="status" className="text-orange-300 uppercase tracking-wider">Raw evidence: unredacted, this view is audited</span>
          : <span data-testid="redacted-banner" className="text-white/60 uppercase tracking-wider">Redacted view (secrets and personal data masked)</span>}
        {canRaw && (
          <button type="button" data-testid="toggle-raw" className="border border-white/25 px-2 py-1 uppercase tracking-wider hover:bg-white/10" aria-pressed={wantRaw} onClick={() => setWantRaw(value => !value)}>
            {wantRaw ? 'Back to redacted' : 'Show raw (audited)'}
          </button>
        )}
        {canRaw && !wantRaw && <span className="text-white/60">Showing raw evidence is recorded in the audit log.</span>}
        {rawDenied && <span role="alert" className="text-red-300">Raw evidence is not permitted for your account.</span>}
      </div>
      <div className="p-4 space-y-4 max-h-[32rem] overflow-y-auto">
        {error && <ErrorNotice message={error} />}
        {!detail && !error && <p className="text-xs text-white/60">Loading transcript…</p>}
        {turns.map(turn => {
          const hit = turn.monitor_hits.length > 0
          const failing = failingTurn === turn.index
          return (
            <article key={turn.index} data-testid={`turn-${turn.index}`} data-hit={hit} data-failing={failing}
              className={`border-l-2 pl-3 ${failing ? 'border-red-500' : hit ? 'border-orange-400' : 'border-white/10'}`}>
              <div className="text-[9px] uppercase tracking-wider text-white/60">
                Turn {turn.index + 1}{turn.http_status ? ` · HTTP ${turn.http_status}` : ''} · {formatDuration(turn.latency_ms)}
                {failing && <span className="ml-2 text-red-400">first failing turn</span>}
              </div>
              <div className="mt-2 max-w-[85%] bg-white/[0.06] px-3 py-2 text-xs whitespace-pre-wrap break-words">{turn.message}</div>
              <div className="mt-2 ml-auto max-w-[85%] border border-white/10 px-3 py-2 text-xs whitespace-pre-wrap break-words text-white/80">
                {turn.response_text || <span className="text-white/60">(empty reply)</span>}
              </div>
              {turn.tool_calls.length > 0 && (
                <p className="mt-1 text-[10px] text-white/60">tool calls: {turn.tool_calls.map(call => call.name).join(', ')}</p>
              )}
              {turn.error && <p className="mt-1 text-[10px] text-red-300">error: {turn.error}</p>}
              {hit && (
                <ul className="mt-1 flex flex-wrap gap-2" aria-label="Monitor hits">
                  {turn.monitor_hits.map(name => <li key={name}><Badge className="text-orange-300 border-orange-500/50 bg-orange-950/30">hit: {name}</Badge></li>)}
                </ul>
              )}
            </article>
          )
        })}
        {detail && turns.length === 0 && <p className="text-xs text-white/60">No turns recorded yet.</p>}
      </div>
      {verdict && (
        <footer className="border-t border-white/10 px-4 py-3 text-xs text-white/60">
          <span className="text-white/60 uppercase text-[9px] tracking-wider">Rationale </span>{verdict.rationale}
          <span className="ml-3 text-white/60">judge agreement {(verdict.judge_agreement * 100).toFixed(0)}%</span>
        </footer>
      )}
    </section>
  )
}
