import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { Card, Notice, Page, PageHeader } from '../components/layout'
import { AsiBadge, EmptyState, ErrorState, Field, SkeletonList, buttonClass, cx, inputClass, primaryButtonClass } from '../components/ui'
import { createCampaign, listTargets } from '../lib/api'
import type { CampaignPolicy } from '../lib/contracts'
import { estimateCampaign, formatSeconds } from '../lib/estimate'
import { applySafeDefaults, defaultPolicy, isForbiddenInProduction, validatePolicy } from '../lib/safeDefaults'
import { TECHNIQUE_GROUPS } from '../lib/techniqueGroups'
import { useLoad } from '../lib/useLoad'
import { can, PERMISSION, useMe } from '../lib/useMe'

type NumberKey = 'trials_per_technique' | 'max_turns' | 'max_parallel_conversations' | 'max_total_requests' | 'rate_limit_rps' | 'max_llm_cost_usd'

export default function CampaignNewPage() {
  const navigate = useNavigate()
  const [search] = useSearchParams()
  const { me } = useMe()
  const { data: targets, error: loadError, loading, reload } = useLoad(() => listTargets().then(r => r.items), 'targets')
  const [targetId, setTargetId] = useState(search.get('target') ?? '')
  const [policy, setPolicy] = useState<CampaignPolicy>(() => defaultPolicy('staging'))
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const target = targets?.find(item => item.target_id === targetId)
  const environment = target?.environment ?? 'staging'
  const production = environment === 'production'

  // Switching to a production target forces the safe defaults.
  useEffect(() => { setPolicy(previous => applySafeDefaults(previous, environment)) }, [environment])

  const problems = useMemo(() => validatePolicy(policy, environment), [policy, environment])
  const estimate = useMemo(() => estimateCampaign(policy), [policy])
  const set = <K extends keyof CampaignPolicy>(key: K, value: CampaignPolicy[K]) => setPolicy(previous => ({ ...previous, [key]: value }))
  const toggle = (id: string) => set('techniques', policy.techniques.includes(id) ? policy.techniques.filter(t => t !== id) : [...policy.techniques, id])
  const number = (key: NumberKey) => (event: React.ChangeEvent<HTMLInputElement>) => set(key, Number(event.target.value))

  const launch = async () => {
    if (!target) return
    setSubmitting(true)
    setError(null)
    try {
      const { campaign_id } = await createCampaign({ target_id: target.target_id, policy: applySafeDefaults(policy, environment) })
      navigate(`/campaigns/${campaign_id}`)
    } catch (e) {
      setError((e as Error).message)
      setSubmitting(false)
    }
  }

  if (me && !can(me, PERMISSION.campaignsLaunch)) {
    return <Page><PageHeader title="New campaign" /><Notice>Your role ({me.role}) cannot launch campaigns. Ask an operator.</Notice></Page>
  }

  const lockHint = (text: string) => production ? `Locked for production: ${text}` : undefined
  const verified = targets?.filter(t => t.verified) ?? []

  return (
    <Page>
      <PageHeader eyebrow="Campaign builder" title="New campaign" description="Pick a verified target, the techniques to try and the budget. Canary stops as soon as any limit is reached." />
      {loadError && <ErrorState title="Could not load targets" message={loadError} onRetry={reload} />}
      {loading && !targets && !loadError && <SkeletonList rows={5} label="Loading targets" />}
      {targets && verified.length === 0 && (
        <EmptyState title="No verified targets" description="Campaigns only run against agents you own. Verify ownership of a target first." action={<Link to="/targets" className={primaryButtonClass}>Go to targets</Link>} />
      )}
      {targets && verified.length > 0 && (
        <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
          <div className="min-w-0 space-y-6">
            {error && <ErrorState title="Could not launch the campaign" message={error} />}

            <Card className="space-y-3">
              <Field label="Target">
                <select className={inputClass} value={targetId} onChange={event => setTargetId(event.target.value)}>
                  <option value="">Select a verified target…</option>
                  {targets.map(item => <option key={item.target_id} value={item.target_id} disabled={!item.verified}>{item.name} ({item.environment}){item.verified ? '' : ' - unverified'}</option>)}
                </select>
              </Field>
              {targets.some(item => !item.verified) && <p className="text-xs text-muted">Unverified targets cannot be attacked. <Link className="underline" to="/targets">Verify ownership first.</Link></p>}
            </Card>

            {production && (
              <div data-testid="production-notice"><Notice>
                <strong>Production target: safe defaults are locked.</strong> Real users may share this system, so Canary caps load and avoids damage:
                <ul className="mt-1 list-disc space-y-0.5 pl-5">
                  <li>At most 1 request per second, so the target is never flooded.</li>
                  <li>At most 2 parallel conversations, so one campaign cannot exhaust its capacity.</li>
                  <li>At most 300 requests in total, so the blast radius stays bounded.</li>
                  <li>Destructive tools are off and resource-exhaustion techniques are staging-only.</li>
                </ul>
                Every request carries an <code className="rounded-sm bg-raised px-1 font-mono text-xs">X-Canary-Campaign</code> header so the owner can filter this traffic. The backend enforces the same limits.
              </Notice></div>
            )}

            <Card>
              <h2 className="mb-1 text-base font-semibold">Techniques</h2>
              <p className="mb-4 text-xs text-muted">{policy.techniques.length} selected</p>
              <div className="space-y-5">
                {TECHNIQUE_GROUPS.map(group => (
                  <fieldset key={group.id}>
                    <legend className="font-semibold">{group.title}</legend>
                    <p className="mb-2 text-xs text-muted">{group.blurb}</p>
                    <div className="grid gap-2 sm:grid-cols-2">
                      {group.techniques.map(technique => {
                        const blocked = production && isForbiddenInProduction(technique.id)
                        return (
                          <label key={technique.id} className={cx('flex gap-3 rounded-md border p-3 text-sm has-[:checked]:border-fg has-[:checked]:bg-raised', blocked ? 'cursor-not-allowed border-line bg-raised opacity-70' : 'cursor-pointer border-line-strong hover:bg-raised')}>
                            <input type="checkbox" className="mt-1 h-4 w-4 shrink-0 accent-accent" disabled={blocked} checked={policy.techniques.includes(technique.id)} onChange={() => toggle(technique.id)} />
                            <span className="min-w-0">
                              <span className="flex flex-wrap items-center gap-2 font-medium">{technique.name} <AsiBadge code={technique.asiCode} /></span>
                              <span className="mt-0.5 block text-xs text-muted">{blocked ? 'Staging only: locked on production' : technique.description}</span>
                            </span>
                          </label>
                        )
                      })}
                    </div>
                  </fieldset>
                ))}
              </div>
            </Card>

            <Card className="space-y-4">
              <h2 className="text-base font-semibold">Budget and limits</h2>
              <div className="grid gap-4 sm:grid-cols-3">
                <Field label="Trials per technique"><input type="number" min={1} max={50} className={inputClass} value={policy.trials_per_technique} onChange={number('trials_per_technique')} /></Field>
                <Field label="Max turns"><input type="number" min={1} max={30} className={inputClass} value={policy.max_turns} onChange={number('max_turns')} /></Field>
                <Field label="LLM budget (USD)"><input type="number" min={0.5} step={0.5} className={inputClass} value={policy.max_llm_cost_usd} onChange={number('max_llm_cost_usd')} /></Field>
                <Field label="Rate limit (req/s)" hint={lockHint('at most 1')}><input type="number" min={0.1} step={0.1} disabled={production} className={inputClass} value={policy.rate_limit_rps} onChange={number('rate_limit_rps')} /></Field>
                <Field label="Parallel conversations" hint={lockHint('at most 2')}><input type="number" min={1} disabled={production} className={inputClass} value={policy.max_parallel_conversations} onChange={number('max_parallel_conversations')} /></Field>
                <Field label="Total requests" hint={lockHint('at most 300')}><input type="number" min={1} disabled={production} className={inputClass} value={policy.max_total_requests} onChange={number('max_total_requests')} /></Field>
              </div>
              <div className="space-y-2">
                <label className="flex items-center gap-3"><input type="checkbox" className="h-4 w-4 accent-accent" checked={policy.stop_on_first_confirmed} onChange={event => set('stop_on_first_confirmed', event.target.checked)} /> Stop on first confirmed finding</label>
                <label className={cx('flex items-center gap-3', production && 'text-muted')}><input type="checkbox" className="h-4 w-4 accent-accent" disabled={production} checked={policy.allow_destructive_tools} onChange={event => set('allow_destructive_tools', event.target.checked)} /> Allow destructive tools{production ? ' (never on production)' : ''}</label>
              </div>
            </Card>
          </div>

          <aside aria-label="Estimate and launch" className="space-y-4 lg:sticky lg:top-20">
            <Card className="space-y-3" >
              <h2 className="text-base font-semibold">Estimate</h2>
              <dl data-testid="estimate" aria-live="polite" className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1.5">
                <dt className="text-muted">Conversations</dt><dd className="text-right font-mono">{estimate.conversations}</dd>
                <dt className="text-muted">Target requests (max)</dt><dd className="text-right font-mono">{estimate.requests}</dd>
                <dt className="text-muted">Time (at least)</dt><dd className="text-right font-mono">{formatSeconds(estimate.minSeconds)}</dd>
                <dt className="text-muted">LLM spend (cap)</dt><dd className="text-right font-mono">${estimate.costCapUsd.toFixed(2)}</dd>
              </dl>
              {estimate.truncated && <p className="text-xs text-warn"><span aria-hidden="true">! </span>The request budget ({policy.max_total_requests}) ends the campaign before every turn of every trial runs.</p>}
              <p className="text-xs text-muted">Requests assume one per turn. LLM spend is a hard cap, not a prediction: the campaign stops when it is reached.</p>
            </Card>
            {problems.length > 0 && target && <div role="alert"><ul className="list-disc space-y-0.5 pl-5 text-warn">{problems.map(problem => <li key={problem}>{problem}</li>)}</ul></div>}
            {!target && <p className="text-xs text-muted">Select a target to enable launch.</p>}
            <div className="flex flex-wrap gap-3">
              <button type="button" data-testid="launch" className={primaryButtonClass} disabled={!target || problems.length > 0 || submitting} onClick={launch}>{submitting ? 'Launching…' : 'Launch campaign'}</button>
              <Link to="/campaigns" className={buttonClass}>Cancel</Link>
            </div>
          </aside>
        </div>
      )}
    </Page>
  )
}
