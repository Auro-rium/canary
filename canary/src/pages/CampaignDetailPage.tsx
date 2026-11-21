import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { Badge, buttonClass, ErrorNotice, Metric, Notice, PageHeader, StatusBadge } from '../components/Console'
import { BudgetMeter, ConversationGrid, ResultsTable } from '../components/LiveParts'
import { KillSwitchControl } from '../components/KillSwitch'
import { can, PERMISSION, useMe } from '../lib/useMe'
import { Transcript } from '../components/Transcript'
import { cancelCampaign, getCampaign, reportUrl, streamCampaignEvents } from '../lib/api'
import { emptyCampaign, fromDetail, isCampaignTerminal, reduceEvent, type LiveCampaign } from '../lib/liveState'
import { gutter, pageClass } from '../lib/presentation'
import type { CampaignDetail } from '../lib/v2'

export default function CampaignDetailPage() {
  const { campaignId = '' } = useParams()
  const [search] = useSearchParams()
  const { me } = useMe()
  const [detail, setDetail] = useState<CampaignDetail | null>(null)
  const [live, setLive] = useState<LiveCampaign>(() => emptyCampaign(campaignId))
  const [error, setError] = useState<string | null>(null)
  const [connection, setConnection] = useState<'connected' | 'reconnecting' | 'idle'>('idle')
  const [selected, setSelected] = useState<string | null>(search.get('conversation'))
  const [cancelling, setCancelling] = useState(false)
  const liveRef = useRef(live)
  liveRef.current = live

  // Load the snapshot once, then follow the event stream from its seq.
  useEffect(() => {
    const controller = new AbortController()
    setError(null)
    getCampaign(campaignId)
      .then(snapshot => {
        if (controller.signal.aborted) return
        setDetail(snapshot)
        const state = fromDetail(snapshot)
        setLive(state)
        if (isCampaignTerminal(state.status)) return
        return streamCampaignEvents(campaignId, {
          lastSeq: state.lastSeq,
          signal: controller.signal,
          onStatus: setConnection,
          onEvent: event => setLive(previous => reduceEvent(previous, event)),
        }).then(() => setConnection('idle'))
      })
      .catch(e => { if (!controller.signal.aborted) setError((e as Error).message) })
    return () => controller.abort()
  }, [campaignId])

  const cells = useMemo(() => Object.values(live.cells), [live.cells])
  const techniques = useMemo(
    () => [...new Set([...(detail?.policy.techniques ?? []), ...cells.map(cell => cell.technique)])],
    [detail, cells],
  )
  const selectedCell = selected ? live.cells[selected] : undefined
  const terminal = isCampaignTerminal(live.status)
  const canControl = can(me, PERMISSION.campaignsCancel)

  const cancel = useCallback(async () => {
    setCancelling(true)
    try { await cancelCampaign(campaignId) } catch (e) { setError((e as Error).message) } finally { setCancelling(false) }
  }, [campaignId])

  return (
    <main className={pageClass}>
      <PageHeader eyebrow="Live campaign" title={detail?.target_name ?? 'Campaign'}>
        <StatusBadge status={live.status} />
        {detail?.environment === 'production' && <StatusBadge status="production" />}
        {canControl && !terminal && (
          <button type="button" data-testid="cancel-campaign" disabled={cancelling} onClick={cancel} className={buttonClass}>Cancel campaign</button>
        )}
        {can(me, PERMISSION.killSwitchWrite) && <KillSwitchControl />}
      </PageHeader>

      <section className={`${gutter} py-6 space-y-4 border-b border-white/10`}>
        {error && <ErrorNotice message={error} />}
        {connection === 'reconnecting' && <Notice>Connection lost; reconnecting and resuming from the last event.</Notice>}
        {live.status === 'failed' && <ErrorNotice message={`Campaign failed: ${live.message ?? 'unknown error'}`} />}
        {live.status === 'cancelled' && <Notice>Campaign cancelled{live.cancelledReason ? ` (${live.cancelledReason.replace('_', ' ')})` : ''}.</Notice>}
        <div className="flex flex-wrap gap-3">
          <Metric label="Conversations" value={`${cells.length} / ${live.totalConversations || detail?.total_conversations || '—'}`} />
          <Metric label="Confirmed" value={live.confirmed} tone={live.confirmed > 0 ? 'danger' : 'default'} />
          <Metric label="Running" value={cells.filter(cell => cell.status === 'running').length} tone="warning" />
        </div>
        <BudgetMeter budget={live.budget} />
      </section>

      <section className={`${gutter} py-8 grid xl:grid-cols-[auto_1fr] gap-8 border-b border-white/10`}>
        <div>
          <h2 className="mb-3 text-[10px] uppercase tracking-[0.2em] text-white/60">Conversations (technique × trial)</h2>
          {techniques.length === 0
            ? <p className="text-xs text-white/60">Waiting for the first conversation…</p>
            : <ConversationGrid cells={cells} techniques={techniques} trials={detail?.policy.trials_per_technique ?? 1} selected={selected} onSelect={setSelected} />}
        </div>
        <div>{selectedCell ? <Transcript cell={selectedCell} highlightTurn={search.get('turn') !== null ? Number(search.get('turn')) : null} /> : <p className="text-xs text-white/60">Select a cell to read its transcript.</p>}</div>
      </section>

      <section className={`${gutter} py-8`}>
        <div className="flex flex-wrap items-center justify-between gap-3 mb-4">
          <h2 className="text-[10px] uppercase tracking-[0.2em] text-white/60">Results by technique</h2>
          <div className="flex gap-2 items-center">
            <Link to={`/findings?campaign_id=${encodeURIComponent(campaignId)}`} className={buttonClass}>Findings</Link>
            {terminal && (['md', 'json', 'pdf'] as const).map(format => <a key={format} href={reportUrl(campaignId, format)} className="text-[10px] uppercase text-white/50 hover:text-white"><Badge>{format}</Badge></a>)}
          </div>
        </div>
        <ResultsTable results={live.results} />
      </section>
    </main>
  )
}
