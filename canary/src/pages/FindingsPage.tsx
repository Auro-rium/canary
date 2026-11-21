import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Metric, Page, PageHeader } from '../components/Console'
import { AsiBadge, EmptyState, ErrorState, Field, SeverityBadge, SkeletonList, StatusBadge, buttonClass, cx, inputClass, useToast } from '../components/ui'
import { PageControls } from '../components/ui/Table'
import { listFindings, updateFindingStatus } from '../lib/api'
import { ASI_CODE_PATTERN } from '../lib/contracts'
import { formatDate, strategyLabel } from '../lib/presentation'
import { useDebounced } from '../lib/useDebounced'
import { useLoad } from '../lib/useLoad'
import { can, PERMISSION, useMe } from '../lib/useMe'
import type { FindingDetail, FindingStatus, FindingV2 } from '../lib/v2'

const PAGE_SIZE = 50
const STATUSES: FindingStatus[] = ['open', 'needs_review', 'inconclusive', 'wont_fix', 'false_positive']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
// Mirrors storage/v2/repositories.py FINDING_TRANSITIONS; the server is authoritative (409 on an illegal move).
const ALLOWED: Record<FindingStatus, FindingStatus[]> = {
  open: ['needs_review', 'inconclusive', 'wont_fix', 'false_positive'],
  needs_review: ['open', 'wont_fix', 'false_positive'],
  inconclusive: ['open', 'wont_fix', 'false_positive'],
  wont_fix: [],
  false_positive: [],
}
const LIFECYCLE: Record<FindingStatus, { title: string; blurb: string }> = {
  open: { title: 'Open', blurb: 'New, not yet triaged' },
  needs_review: { title: 'Needs review', blurb: 'Waiting for a second look' },
  inconclusive: { title: 'Inconclusive', blurb: 'Judges could not decide' },
  wont_fix: { title: 'Won’t fix', blurb: 'Accepted risk' },
  false_positive: { title: 'False positive', blurb: 'Not a real issue' },
}
const selectClass = `${inputClass} w-auto min-w-[8rem]`

function Transition({ finding, onUpdated }: { finding: FindingV2; onUpdated: (finding: FindingDetail) => void }) {
  const [next, setNext] = useState<FindingStatus | ''>('')
  const [rationale, setRationale] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const toast = useToast()
  const options = ALLOWED[finding.status] ?? []
  if (options.length === 0) return <span className="text-xs text-muted">Terminal lifecycle state</span>
  const needsRationale = next === 'wont_fix' || next === 'false_positive'

  const submit = async () => {
    if (!next) return
    if (needsRationale && !rationale.trim()) { setError('A rationale is required for this transition.'); return }
    setSaving(true)
    setError(null)
    try {
      onUpdated(await updateFindingStatus(finding.finding_id, { status: next, rationale: rationale.trim() || undefined }))
      toast({ title: 'Finding updated', description: `Moved to ${next.replace('_', ' ')}.`, tone: 'ok' })
      setNext('')
      setRationale('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="min-w-0 space-y-2">
      <div className="flex flex-wrap gap-2">
        <select aria-label="Move to status" className={selectClass} value={next} onChange={event => setNext(event.target.value as FindingStatus | '')}>
          <option value="">Move to…</option>{options.map(option => <option key={option} value={option}>{option.replace('_', ' ')}</option>)}
        </select>
        <button type="button" className={buttonClass} disabled={!next || saving} onClick={submit}>Apply</button>
      </div>
      {needsRationale && <input aria-label="Rationale" className={inputClass} placeholder="Rationale (stored with your identity)" value={rationale} onChange={event => setRationale(event.target.value)} />}
      {error && <p role="alert" className="text-xs text-danger"><span aria-hidden="true">✕ </span>{error}</p>}
    </div>
  )
}

/** Deep link to the exact turn that failed: the live view opens the transcript drawer scrolled to it. */
const transcriptLink = (finding: FindingV2) =>
  `/campaigns/${encodeURIComponent(finding.campaign_id ?? '')}?conversation=${encodeURIComponent(finding.conversation_id ?? '')}${finding.first_failing_turn !== null ? `&turn=${finding.first_failing_turn}` : ''}`

function FindingCard({ finding, canReview, onUpdated, compact }: { finding: FindingV2; canReview: boolean; onUpdated: (finding: FindingDetail) => void; compact?: boolean }) {
  return (
    <li data-testid="finding" className="min-w-0 rounded-lg border border-line bg-surface p-4 shadow-e1">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <AsiBadge code={finding.asi_class} />
        <StatusBadge status={finding.status} />
        {!compact && <span className="ml-auto text-xs text-muted">{formatDate(finding.created_at)}</span>}
      </div>
      <h3 className="mt-2 break-words font-semibold">{finding.title || strategyLabel(finding.technique)}</h3>
      <p className={cx('mt-1 whitespace-pre-wrap break-words text-muted', compact && 'line-clamp-3')}>{finding.rationale}</p>
      <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
        {finding.campaign_id && finding.conversation_id
          ? <Link className="text-xs font-medium underline underline-offset-2" to={transcriptLink(finding)}>
              Open transcript{finding.first_failing_turn !== null ? ` at turn ${finding.first_failing_turn + 1}` : ''}
            </Link>
          : <span className="text-xs text-muted">No transcript linked</span>}
        {canReview ? <Transition finding={finding} onUpdated={onUpdated} /> : <span className="text-xs text-muted">Read-only role</span>}
      </div>
      {finding.reviewer_id && <p className="mt-2 text-xs text-muted">Last reviewed by {finding.reviewer_id}</p>}
    </li>
  )
}

export default function FindingsPage() {
  const [search, setSearch] = useSearchParams()
  const { me } = useMe()
  const page = Number(search.get('page') ?? '1') || 1
  const severity = search.get('severity') ?? ''
  const status = search.get('status') ?? ''
  const campaignId = search.get('campaign_id') ?? ''
  const urlAsi = search.get('asi_class') ?? ''
  const view = search.get('view') === 'board' ? 'board' : 'list'

  // The ASI input is typed freely; only a debounced, valid value reaches the URL and the API.
  const [asiInput, setAsiInput] = useState(urlAsi)
  const asiDebounced = useDebounced(asiInput.trim().toUpperCase(), 350)
  useEffect(() => {
    const valid = ASI_CODE_PATTERN.test(asiDebounced) ? asiDebounced : ''
    if (valid === urlAsi) return
    const params = new URLSearchParams(search)
    if (valid) params.set('asi_class', valid); else params.delete('asi_class')
    params.set('page', '1')
    setSearch(params, { replace: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [asiDebounced])

  const key = [page, severity, status, urlAsi, campaignId].join('|')
  const { data, error, loading, reload, setData } = useLoad(() => {
    const query = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) })
    if (severity) query.set('severity', severity)
    if (status) query.set('status', status)
    if (urlAsi) query.set('asi_class', urlAsi)
    if (campaignId) query.set('campaign_id', campaignId)
    return listFindings(query)
  }, key)

  const setParam = (name: string, value: string) => {
    const params = new URLSearchParams(search)
    if (value) params.set(name, value); else params.delete(name)
    if (name !== 'page' && name !== 'view') params.set('page', '1')
    setSearch(params)
  }
  const replace = (updated: FindingDetail) => setData(previous => previous && { ...previous, items: previous.items.map(item => item.finding_id === updated.finding_id ? { ...item, ...updated } : item) })
  const canReview = can(me, PERMISSION.findingsTriage)
  const asiInvalid = asiInput.trim() !== '' && !ASI_CODE_PATTERN.test(asiInput.trim().toUpperCase())
  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1
  const toggle = (value: 'list' | 'board') => cx(buttonClass, 'rounded-none first:rounded-l-md last:rounded-r-md', view === value && 'bg-raised ring-1 ring-fg')

  return (
    <Page wide>
      <PageHeader title="Findings" description="Confirmed and suspected failures, with the exact turn that failed. Triage moves a finding through its lifecycle.">
        <div role="group" aria-label="View" className="inline-flex">
          <button type="button" className={toggle('list')} aria-pressed={view === 'list'} onClick={() => setParam('view', '')}>List</button>
          <button type="button" className={toggle('board')} aria-pressed={view === 'board'} onClick={() => setParam('view', 'board')}>Lifecycle board</button>
        </div>
      </PageHeader>

      <section aria-label="Filters" className="mb-4 flex flex-wrap items-end gap-3">
        <Metric label="Total" value={data?.total ?? '—'} />
        <Metric label="Page" value={`${page} / ${totalPages}`} />
        <Field label="Severity"><select className={selectClass} value={severity} onChange={event => setParam('severity', event.target.value)}><option value="">All</option>{SEVERITIES.map(value => <option key={value}>{value}</option>)}</select></Field>
        <Field label="Status"><select className={selectClass} value={status} onChange={event => setParam('status', event.target.value)}><option value="">All</option>{STATUSES.map(value => <option key={value} value={value}>{value.replace('_', ' ')}</option>)}</select></Field>
        <Field label="ASI class" hint={asiInvalid ? 'Use ASI01 to ASI10' : undefined}><input className={`${inputClass} w-28`} placeholder="ASI01" value={asiInput} onChange={event => setAsiInput(event.target.value)} /></Field>
        {campaignId && <button type="button" className={buttonClass} onClick={() => setParam('campaign_id', '')}>Clear campaign filter</button>}
      </section>

      {error && <ErrorState title="Could not load findings" message={error} onRetry={reload} />}
      {loading && !data && !error && <SkeletonList rows={4} label="Loading findings" />}
      {data?.items.length === 0 && <EmptyState title="No findings match these filters" description="Clear a filter, or run a campaign to produce findings." />}

      {data && data.items.length > 0 && view === 'list' && (
        <ul className="space-y-3">
          {data.items.map(finding => <FindingCard key={finding.finding_id} finding={finding} canReview={canReview} onUpdated={replace} />)}
        </ul>
      )}

      {data && data.items.length > 0 && view === 'board' && (
        <>
          <p className="mb-3 text-xs text-muted">The {data.items.length} findings on this page, grouped by lifecycle status.</p>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5" data-testid="lifecycle-board">
            {STATUSES.map(column => {
              const items = data.items.filter(item => item.status === column)
              return (
                <section key={column} aria-label={LIFECYCLE[column].title} className="min-w-0 rounded-lg bg-raised p-2">
                  <h2 className="px-1 font-semibold">{LIFECYCLE[column].title} <span className="font-normal text-muted">({items.length})</span></h2>
                  <p className="mb-2 px-1 text-xs text-muted">{LIFECYCLE[column].blurb}</p>
                  {items.length === 0 ? <p className="px-1 py-2 text-xs text-muted">None on this page</p>
                    : <ul className="space-y-2">{items.map(finding => <FindingCard key={finding.finding_id} finding={finding} canReview={canReview} onUpdated={replace} compact />)}</ul>}
                </section>
              )
            })}
          </div>
        </>
      )}

      {data && data.total > 0 && <PageControls paging={{ page, pageSize: data.page_size, total: data.total, onPageChange: next => setParam('page', String(next)) }} />}
    </Page>
  )
}
