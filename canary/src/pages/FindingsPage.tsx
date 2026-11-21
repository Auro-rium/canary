import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Badge, buttonClass, EmptyState, ErrorNotice, Field, inputClass, Metric, PageHeader, StatusBadge } from '../components/Console'
import { can, PERMISSION, useMe } from '../lib/useMe'
import { listFindings, updateFindingStatus } from '../lib/api'
import { ASI_CODE_PATTERN } from '../lib/contracts'
import { formatDate, gutter, pageClass, SEVERITY_STYLE, strategyLabel } from '../lib/presentation'
import { useDebounced } from '../lib/useDebounced'
import type { FindingDetail, FindingStatus, FindingV2, Paged } from '../lib/v2'

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

function Transition({ finding, onUpdated }: { finding: FindingV2; onUpdated: (finding: FindingDetail) => void }) {
  const [next, setNext] = useState<FindingStatus | ''>('')
  const [rationale, setRationale] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const options = ALLOWED[finding.status] ?? []
  if (options.length === 0) return <span className="text-[10px] text-white/60 uppercase">Terminal lifecycle state</span>
  const needsRationale = next === 'wont_fix' || next === 'false_positive'

  const submit = async () => {
    if (!next) return
    if (needsRationale && !rationale.trim()) { setError('A rationale is required for this transition.'); return }
    setSaving(true)
    setError(null)
    try {
      onUpdated(await updateFindingStatus(finding.finding_id, { status: next, rationale: rationale.trim() || undefined }))
      setNext('')
      setRationale('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        <select aria-label="Move to status" className="bg-black border border-white/20 px-2 py-1.5 text-[10px]" value={next} onChange={event => setNext(event.target.value as FindingStatus | '')}>
          <option value="">Move to…</option>{options.map(option => <option key={option} value={option}>{option.replace('_', ' ')}</option>)}
        </select>
        <button type="button" className={buttonClass} disabled={!next || saving} onClick={submit}>Apply</button>
      </div>
      {needsRationale && <input aria-label="Rationale" className={inputClass} placeholder="Rationale (stored with your identity)" value={rationale} onChange={event => setRationale(event.target.value)} />}
      {error && <ErrorNotice message={error} />}
    </div>
  )
}

export default function FindingsPage() {
  const [search, setSearch] = useSearchParams()
  const { me } = useMe()
  const [data, setData] = useState<Paged<FindingV2> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const page = Number(search.get('page') ?? '1') || 1
  const severity = search.get('severity') ?? ''
  const status = search.get('status') ?? ''
  const campaignId = search.get('campaign_id') ?? ''
  const urlAsi = search.get('asi_class') ?? ''

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

  useEffect(() => {
    const query = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) })
    if (severity) query.set('severity', severity)
    if (status) query.set('status', status)
    if (urlAsi) query.set('asi_class', urlAsi)
    if (campaignId) query.set('campaign_id', campaignId)
    let live = true
    listFindings(query)
      .then(result => { if (live) { setData(result); setError(null) } })
      .catch(e => { if (live) setError((e as Error).message) })
    return () => { live = false }
  }, [page, severity, status, urlAsi, campaignId])

  const setParam = (key: string, value: string) => {
    const params = new URLSearchParams(search)
    if (value) params.set(key, value); else params.delete(key)
    if (key !== 'page') params.set('page', '1')
    setSearch(params)
  }
  const totalPages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1
  const replace = (updated: FindingDetail) => setData(previous => previous && { ...previous, items: previous.items.map(item => item.finding_id === updated.finding_id ? { ...item, ...updated } : item) })
  const canReview = can(me, PERMISSION.findingsTriage)
  const asiInvalid = asiInput.trim() !== '' && !ASI_CODE_PATTERN.test(asiInput.trim().toUpperCase())

  return (
    <main className={pageClass}>
      <PageHeader eyebrow="Finding lifecycle" title="Findings" />
      <section className={`${gutter} py-6 border-b border-white/10 flex flex-wrap gap-4 items-end`}>
        <Metric label="Total" value={data?.total ?? '—'} />
        <Metric label="Page" value={`${page} / ${totalPages}`} />
        <Field label="Severity"><select aria-label="Severity" className="bg-black border border-white/20 px-2 py-2 text-xs" value={severity} onChange={event => setParam('severity', event.target.value)}><option value="">All</option>{SEVERITIES.map(value => <option key={value}>{value}</option>)}</select></Field>
        <Field label="Status"><select aria-label="Status" className="bg-black border border-white/20 px-2 py-2 text-xs" value={status} onChange={event => setParam('status', event.target.value)}><option value="">All</option>{STATUSES.map(value => <option key={value} value={value}>{value.replace('_', ' ')}</option>)}</select></Field>
        <Field label="ASI class" hint={asiInvalid ? 'Use ASI01 to ASI10' : undefined}><input aria-label="ASI class" className="bg-black border border-white/20 px-2 py-2 text-xs w-28" placeholder="ASI01" value={asiInput} onChange={event => setAsiInput(event.target.value)} /></Field>
        {campaignId && <button type="button" className={buttonClass} onClick={() => setParam('campaign_id', '')}>Clear campaign filter</button>}
      </section>
      <section className={`${gutter} py-8`}>
        {error && <ErrorNotice message={error} />}
        {!data && !error && <EmptyState>Loading findings</EmptyState>}
        {data?.items.length === 0 && <EmptyState>No findings match these filters</EmptyState>}
        <ul className="space-y-3">
          {data?.items.map(finding => (
            <li key={finding.finding_id} data-testid="finding" className="border border-white/10 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge className={(SEVERITY_STYLE as Record<string, string>)[finding.severity] ?? SEVERITY_STYLE.info}>{finding.severity}</Badge>
                <Badge>{finding.asi_class}</Badge>
                <StatusBadge status={finding.status} />
                <span className="text-xs">{finding.title || strategyLabel(finding.technique)}</span>
                <span className="ml-auto text-[10px] text-white/60">{formatDate(finding.created_at)}</span>
              </div>
              <p className="mt-2 text-xs text-white/60 whitespace-pre-wrap break-words">{finding.rationale}</p>
              <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
                {finding.campaign_id && finding.conversation_id ? <Link className="text-[11px] underline text-white/70 hover:text-white" to={`/campaigns/${finding.campaign_id ?? ''}?conversation=${encodeURIComponent(finding.conversation_id ?? '')}${finding.first_failing_turn !== null ? `&turn=${finding.first_failing_turn}` : ''}`}>
                  Open transcript{finding.first_failing_turn !== null ? ` at turn ${finding.first_failing_turn + 1}` : ''}
                </Link> : <span className="text-[10px] text-white/60">No transcript linked</span>}
                {canReview ? <Transition finding={finding} onUpdated={replace} /> : <span className="text-[10px] text-white/60">Read-only role</span>}
              </div>
              {finding.reviewer_id && <p className="mt-2 text-[10px] text-white/60">Last reviewed by {finding.reviewer_id}</p>}
            </li>
          ))}
        </ul>
        {data && data.total > 0 && (
          <div className="mt-5 flex items-center justify-between text-xs">
            <button disabled={page <= 1} onClick={() => setParam('page', String(page - 1))} className="border border-white/20 px-3 py-2 disabled:opacity-30">Previous</button>
            <span className="text-white/60">{(page - 1) * data.page_size + 1}–{Math.min(page * data.page_size, data.total)} of {data.total}</span>
            <button disabled={page >= totalPages} onClick={() => setParam('page', String(page + 1))} className="border border-white/20 px-3 py-2 disabled:opacity-30">Next</button>
          </div>
        )}
      </section>
    </main>
  )
}
