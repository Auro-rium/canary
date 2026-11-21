import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { Metric, Notice, Page, PageHeader } from '../components/Console'
import { KillSwitchControl } from '../components/KillSwitch'
import { BudgetMeter, ConnectionIndicator, ConversationGrid, type Connection } from '../components/LiveParts'
import { ResultsTable } from '../components/ResultsTable'
import { Transcript } from '../components/Transcript'
import { Drawer, ErrorState, SkeletonList, StatusBadge, buttonClass, cx, useToast } from '../components/ui'
import { cancelCampaign, getCampaign, reportUrl, streamCampaignEvents } from '../lib/api'
import { emptyCampaign, fromDetail, isCampaignTerminal, reduceEvent, type LiveCampaign } from '../lib/liveState'
import { statusStyle, strategyLabel } from '../lib/presentation'
import { can, PERMISSION, useMe } from '../lib/useMe'
import type { CampaignDetail } from '../lib/v2'

export default function CampaignDetailPage() {
  const { campaignId = '' } = useParams()
  const [search, setSearch] = useSearchParams()
  const { me } = useMe()
  const toast = useToast()
  const [detail, setDetail] = useState<CampaignDetail | null>(null)
  const [live, setLive] = useState<LiveCampaign>(() => emptyCampaign(campaignId))
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [attempt, setAttempt] = useState(0)
  const [connection, setConnection] = useState<Connection>('idle')
  const [cancelling, setCancelling] = useState(false)

  // Selection lives in the URL (?conversation=&turn=) so a failing turn is a shareable deep link.
  const selected = search.get('conversation')
  const turnParam = search.get('turn')
  const highlightTurn = turnParam !== null && turnParam !== '' && Number.isInteger(Number(turnParam)) ? Number(turnParam) : null
  const select = useCallback((conversationId: string | null) => {
    const params = new URLSearchParams(search)
    params.delete('turn')
    if (conversationId) params.set('conversation', conversationId); else params.delete('conversation')
    setSearch(params, { replace: true })
  }, [search, setSearch])

  // Load the snapshot once, then follow the event stream from its seq.
  useEffect(() => {
    const controller = new AbortController()
    setError(null)
    setLoading(true)
    getCampaign(campaignId)
      .then(snapshot => {
        if (controller.signal.aborted) return
        setDetail(snapshot)
        setLoading(false)
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
      .catch(e => { if (!controller.signal.aborted) { setError((e as Error).message); setLoading(false) } })
    return () => controller.abort()
  }, [campaignId, attempt])

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
    try { await cancelCampaign(campaignId) } catch (e) { toast({ title: 'Could not cancel the campaign', description: (e as Error).message, tone: 'danger' }) } finally { setCancelling(false) }
  }, [campaignId, toast])

  const stopped = cells.filter(cell => statusStyle(cell.status).reason && cell.status !== 'cancelled').length

  return (
    <div className={cx(selected && 'xl:pr-drawer')}>
      <Page wide>
        <PageHeader eyebrow="Live campaign" title={detail?.target_name ?? 'Campaign'}>
          <StatusBadge status={live.status} />
          {detail?.environment === 'production' && <StatusBadge status="production" />}
          <ConnectionIndicator connection={connection} finished={terminal} />
          {canControl && !terminal && (
            <button type="button" data-testid="cancel-campaign" disabled={cancelling} onClick={cancel} className={buttonClass}>Cancel campaign</button>
          )}
          {can(me, PERMISSION.killSwitchWrite) && <KillSwitchControl />}
        </PageHeader>

        {error && <div className="mb-4"><ErrorState title="Live updates stopped" message={error} onRetry={() => setAttempt(value => value + 1)} /></div>}
        {loading && !detail && !error && <SkeletonList rows={5} label="Loading campaign" />}
        {detail && (
          <div className="space-y-6">
            {connection === 'reconnecting' && <Notice>Connection lost; reconnecting and resuming from the last event.</Notice>}
            {live.status === 'failed' && <ErrorState title="Campaign failed" message={live.message ?? 'unknown error'} />}
            {live.status === 'cancelled' && <Notice>Campaign cancelled{live.cancelledReason ? ` (${live.cancelledReason.replace('_', ' ')})` : ''}.</Notice>}

            <section aria-label="Progress" className="space-y-4 rounded-lg border border-line bg-surface p-4">
              <div className="flex flex-wrap gap-3">
                <Metric label="Conversations" value={`${cells.length} / ${live.totalConversations || detail.total_conversations || '—'}`} />
                <Metric label="Confirmed" value={live.confirmed} tone={live.confirmed > 0 ? 'danger' : 'default'} />
                <Metric label="Running" value={cells.filter(cell => cell.status === 'running').length} tone="warning" />
                <Metric label="Stopped early" value={stopped} />
              </div>
              <BudgetMeter budget={live.budget} />
            </section>

            <section aria-labelledby="grid-title">
              <h2 id="grid-title" className="mb-1 text-base font-semibold">Conversations (technique × trial)</h2>
              <p className="mb-3 text-xs text-muted">Select a cell to read its transcript. Each cell shows its status in words as well as color.</p>
              {techniques.length === 0
                ? <p className="text-muted">Waiting for the first conversation…</p>
                : <ConversationGrid cells={cells} techniques={techniques} trials={detail.policy.trials_per_technique ?? 1} selected={selected} onSelect={select} />}
            </section>

            <section aria-labelledby="results-title">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                <h2 id="results-title" className="text-base font-semibold">Results by technique</h2>
                <div className="flex flex-wrap items-center gap-2">
                  <Link to={`/campaigns/${encodeURIComponent(campaignId)}/results`} className={buttonClass}>Full results</Link>
                  <Link to={`/findings?campaign_id=${encodeURIComponent(campaignId)}`} className={buttonClass}>Findings</Link>
                  {terminal && (['md', 'json', 'pdf'] as const).map(format => (
                    <a key={format} href={reportUrl(campaignId, format)} className={buttonClass} aria-label={`Download ${format.toUpperCase()} report`}>{format.toUpperCase()}</a>
                  ))}
                </div>
              </div>
              <ResultsTable results={live.results} />
            </section>
          </div>
        )}
      </Page>

      <Drawer open={!!selected} onClose={() => select(null)} testId="transcript-drawer"
        title={selectedCell ? `${strategyLabel(selectedCell.technique)} · trial ${selectedCell.trial_index + 1}` : 'Transcript'}>
        {selectedCell
          ? <Transcript cell={selectedCell} highlightTurn={highlightTurn} />
          : <div className="p-4"><SkeletonList rows={3} label="Waiting for this conversation" /></div>}
      </Drawer>
    </div>
  )
}
