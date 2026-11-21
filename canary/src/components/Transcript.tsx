import { useEffect, useRef, useState } from 'react'
import { ApiError, getConversation } from '../lib/api'
import type { LiveCell } from '../lib/liveState'
import { formatDuration, statusStyle, VERDICT_STYLE } from '../lib/presentation'
import { can, PERMISSION, useMe } from '../lib/useMe'
import type { ConversationDetail } from '../lib/v2'
import { AsiBadge, Badge, CodeBlock, ErrorState, SeverityBadge, SkeletonList, buttonClass, cx } from './ui'

/**
 * The reason a conversation ended, in words. Prefers the monitor hit that stopped it (live events),
 * falling back to the first turn that carries a hit when the snapshot came from the API.
 */
export function StopReason({ cell, detail }: { cell: LiveCell; detail: ConversationDetail | null }) {
  const style = statusStyle(cell.status)
  if (!style.reason) return null
  const stopper = cell.hits.find(hit => hit.stops_conversation)
  const turnWithHit = detail?.conversation.turns.find(turn => turn.monitor_hits.length > 0)
  const detailText = stopper
    ? `Monitor "${stopper.hit}" (${stopper.severity}) fired on turn ${stopper.turn_index + 1}.`
    : cell.status === 'stopped_monitor' && turnWithHit ? `Monitor "${turnWithHit.monitor_hits[0]}" fired on turn ${turnWithHit.index + 1}.` : null
  return (
    <div data-testid="stop-reason" className="border-b border-line bg-danger-soft px-4 py-2.5 text-danger">
      <p className="font-semibold"><span aria-hidden="true">■ </span>{style.label}</p>
      <p className="text-xs">{style.reason}{detailText ? ` ${detailText}` : ''}</p>
    </div>
  )
}

/** Chat transcript for one conversation, turn by turn, with monitor hits and the first failing turn highlighted. Text only: never parsed as markup. */
export function Transcript({ cell, highlightTurn }: { cell: LiveCell; highlightTurn?: number | null }) {
  const [detail, setDetail] = useState<ConversationDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const id = cell.conversation_id
  const { me } = useMe()
  const canRaw = can(me, PERMISSION.evidenceReadRaw)
  // Redacted by default; raw is opt-in per conversation and never persisted across selections.
  const [wantRaw, setWantRaw] = useState(false)
  const [rawDenied, setRawDenied] = useState(false)
  useEffect(() => { setWantRaw(false); setRawDenied(false); setDetail(null) }, [id])
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

  // Deep links (?turn=N) scroll the failing turn into view once the transcript is there.
  const scrolled = useRef<string | null>(null)
  useEffect(() => {
    if (highlightTurn === null || highlightTurn === undefined || turns.length === 0 || scrolled.current === id) return
    scrolled.current = id
    document.getElementById(`turn-${highlightTurn}`)?.scrollIntoView({ block: 'center' })
  }, [highlightTurn, turns.length, id])

  const status = statusStyle(cell.status)

  return (
    <section data-testid="transcript" aria-label="Conversation transcript">
      <StopReason cell={cell} detail={detail} />
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-2.5 text-xs">
        <Badge tone={status.tone} icon={status.icon}>{cell.status.replace(/_/g, ' ')}</Badge>
        {verdict && <Badge tone={VERDICT_STYLE[verdict.verdict].tone} icon={VERDICT_STYLE[verdict.verdict].icon}>{verdict.verdict}</Badge>}
        {verdict && <SeverityBadge severity={verdict.severity} />}
        {verdict && <AsiBadge code={verdict.asi_class} />}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-4 py-2.5 text-xs">
        {detail?.raw
          ? <span data-testid="raw-banner" role="status" className="font-semibold text-warn"><span aria-hidden="true">! </span>Raw evidence: unredacted, this view is audited</span>
          : <span data-testid="redacted-banner" className="text-muted"><span aria-hidden="true">◐ </span>Redacted view (secrets and personal data masked)</span>}
        {canRaw && (
          <button type="button" data-testid="toggle-raw" className={cx(buttonClass, 'px-2.5 py-1 text-xs')} aria-pressed={wantRaw} onClick={() => setWantRaw(value => !value)}>
            {wantRaw ? 'Back to redacted' : 'Show raw (audited)'}
          </button>
        )}
        {canRaw && !wantRaw && <span className="text-muted">Showing raw evidence is recorded in the audit log.</span>}
        {rawDenied && <span role="alert" className="font-semibold text-danger">Raw evidence is not permitted for your account.</span>}
      </div>
      <div className="space-y-4 p-4">
        {error && <ErrorState title="Could not load the transcript" message={error} />}
        {!detail && !error && <SkeletonList rows={3} label="Loading transcript" />}
        {turns.map(turn => {
          const hit = turn.monitor_hits.length > 0
          const failing = failingTurn === turn.index
          return (
            <article key={turn.index} id={`turn-${turn.index}`} data-testid={`turn-${turn.index}`} data-hit={hit} data-failing={failing}
              className={cx('rounded-md border-l-4 bg-surface pl-3', failing ? 'border-danger bg-danger-soft/40' : hit ? 'border-warn' : 'border-line-strong/60')}>
              <div className="flex flex-wrap items-center gap-x-2 text-xs text-muted">
                <span className="font-semibold text-fg">Turn {turn.index + 1}</span>
                <span>{turn.http_status ? `HTTP ${turn.http_status} · ` : ''}{formatDuration(turn.latency_ms)}</span>
                {failing && <Badge tone="danger" icon="✕">first failing turn</Badge>}
              </div>
              <p className="mt-2 text-xs font-semibold text-muted">Attacker sent</p>
              <CodeBlock text={turn.message} className="mt-0.5 rounded-md bg-raised px-3 py-2" />
              <p className="mt-2 text-xs font-semibold text-muted">Target replied</p>
              <div className="mt-0.5 rounded-md border border-line px-3 py-2">
                {turn.response_text ? <CodeBlock text={turn.response_text} /> : <span className="text-xs text-muted">(empty reply)</span>}
              </div>
              {turn.tool_calls.length > 0 && <p className="mt-1 text-xs text-muted">tool calls: {turn.tool_calls.map(call => call.name).join(', ')}</p>}
              {turn.error && <p className="mt-1 text-xs text-danger">error: {turn.error}</p>}
              {hit && (
                <ul className="mt-2 flex flex-wrap gap-2 pb-1" aria-label="Monitor hits">
                  {turn.monitor_hits.map(name => <li key={name}><Badge tone="warn" icon="▲" mono>hit: {name}</Badge></li>)}
                </ul>
              )}
            </article>
          )
        })}
        {detail && turns.length === 0 && <p className="text-xs text-muted">No turns recorded yet.</p>}
      </div>
      {verdict && (
        <footer className="border-t border-line px-4 py-3 text-xs text-muted">
          <span className="font-semibold">Rationale: </span><span className="break-words">{verdict.rationale}</span>
          <span className="ml-3">judge agreement {(verdict.judge_agreement * 100).toFixed(0)}%</span>
        </footer>
      )}
    </section>
  )
}
