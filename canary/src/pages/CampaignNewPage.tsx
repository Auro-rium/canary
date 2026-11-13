import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { buttonClass, ErrorNotice, Field, inputClass, Notice, PageHeader, primaryButtonClass } from '../components/Console'
import { hasRole, useMe } from '../lib/useMe'
import { createCampaign, listTargets } from '../lib/api'
import type { CampaignPolicy } from '../lib/contracts'
import { gutter, pageClass } from '../lib/presentation'
import { applySafeDefaults, defaultPolicy, isForbiddenInProduction, validatePolicy } from '../lib/safeDefaults'
import { TECHNIQUES } from '../lib/techniques'
import type { TargetView } from '../lib/v2'

export default function CampaignNewPage() {
  const navigate = useNavigate()
  const [search] = useSearchParams()
  const { me } = useMe()
  const [targets, setTargets] = useState<TargetView[]>([])
  const [targetId, setTargetId] = useState(search.get('target') ?? '')
  const [policy, setPolicy] = useState<CampaignPolicy>(() => defaultPolicy('staging'))
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => { listTargets().then(result => setTargets(result.items)).catch(e => setError((e as Error).message)) }, [])

  const target = targets.find(item => item.target_id === targetId)
  const environment = target?.environment ?? 'staging'
  const production = environment === 'production'

  // Switching to a production target forces the safe defaults.
  useEffect(() => { setPolicy(previous => applySafeDefaults(previous, environment)) }, [environment])

  const problems = useMemo(() => validatePolicy(policy, environment), [policy, environment])
  const set = <K extends keyof CampaignPolicy>(key: K, value: CampaignPolicy[K]) => setPolicy(previous => ({ ...previous, [key]: value }))
  const toggle = (id: string) => set('techniques', policy.techniques.includes(id) ? policy.techniques.filter(t => t !== id) : [...policy.techniques, id])
  const number = (key: 'trials_per_technique' | 'max_turns' | 'max_parallel_conversations' | 'max_total_requests' | 'rate_limit_rps' | 'max_llm_cost_usd') =>
    (event: React.ChangeEvent<HTMLInputElement>) => set(key, Number(event.target.value))

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

  if (me && !hasRole(me.role, 'operator', 'admin')) {
    return <main className={pageClass}><PageHeader eyebrow="Campaign builder" title="New campaign" /><section className={`${gutter} py-8`}><Notice>Your role ({me.role}) cannot launch campaigns. Ask an operator.</Notice></section></main>
  }

  return (
    <main className={pageClass}>
      <PageHeader eyebrow="Campaign builder" title="New campaign" />
      <section className={`${gutter} py-8 max-w-4xl space-y-8`}>
        {error && <ErrorNotice message={error} />}

        <Field label="Target">
          <select aria-label="Target" className={inputClass} value={targetId} onChange={event => setTargetId(event.target.value)}>
            <option value="">Select a verified target…</option>
            {targets.map(item => <option key={item.target_id} value={item.target_id} disabled={!item.verified}>{item.name} ({item.environment}){item.verified ? '' : ' - unverified'}</option>)}
          </select>
        </Field>
        {targets.some(item => !item.verified) && <p className="text-[10px] text-white/40">Unverified targets cannot be attacked. <Link className="underline" to="/targets">Verify ownership first.</Link></p>}

        {production && (
          <div data-testid="production-notice"><Notice>
            Production target: safe defaults are enforced and these controls are locked. At most 1 request/second, 2 parallel conversations
            and 300 requests in total; destructive tools are off and resource-exhaustion techniques are staging-only. Every request carries
            an <code>X-Canary-Campaign</code> header so the owner can filter this traffic.
          </Notice></div>
        )}

        <fieldset>
          <legend className="text-[10px] uppercase tracking-wider text-white/50 mb-2">Techniques</legend>
          <div className="grid sm:grid-cols-2 gap-2">
            {TECHNIQUES.map(technique => {
              const blocked = production && isForbiddenInProduction(technique.id)
              return (
                <label key={technique.id} className={`border px-3 py-2 text-xs flex gap-3 ${blocked ? 'opacity-40 border-white/10' : 'border-white/20 cursor-pointer'}`}>
                  <input type="checkbox" disabled={blocked} checked={policy.techniques.includes(technique.id)} onChange={() => toggle(technique.id)} />
                  <span><span className="block">{technique.name} <span className="text-white/30">{technique.asiCode}</span></span><span className="block text-white/40">{blocked ? 'Staging only' : technique.description}</span></span>
                </label>
              )
            })}
          </div>
        </fieldset>

        <div className="grid sm:grid-cols-3 gap-4">
          <Field label="Trials per technique"><input type="number" min={1} max={50} className={inputClass} value={policy.trials_per_technique} onChange={number('trials_per_technique')} /></Field>
          <Field label="Max turns"><input type="number" min={1} max={30} className={inputClass} value={policy.max_turns} onChange={number('max_turns')} /></Field>
          <Field label="LLM budget (USD)"><input type="number" min={0.5} step={0.5} className={inputClass} value={policy.max_llm_cost_usd} onChange={number('max_llm_cost_usd')} /></Field>
          <Field label="Rate limit (req/s)" hint={production ? 'Locked: production ≤ 1' : undefined}><input type="number" min={0.1} step={0.1} disabled={production} className={inputClass} value={policy.rate_limit_rps} onChange={number('rate_limit_rps')} /></Field>
          <Field label="Parallel conversations" hint={production ? 'Locked: production ≤ 2' : undefined}><input type="number" min={1} disabled={production} className={inputClass} value={policy.max_parallel_conversations} onChange={number('max_parallel_conversations')} /></Field>
          <Field label="Total requests" hint={production ? 'Locked: production ≤ 300' : undefined}><input type="number" min={1} disabled={production} className={inputClass} value={policy.max_total_requests} onChange={number('max_total_requests')} /></Field>
        </div>

        <div className="space-y-2 text-xs">
          <label className="flex gap-3"><input type="checkbox" checked={policy.stop_on_first_confirmed} onChange={event => set('stop_on_first_confirmed', event.target.checked)} /> Stop on first confirmed finding</label>
          <label className={`flex gap-3 ${production ? 'opacity-50' : ''}`}><input type="checkbox" disabled={production} checked={policy.allow_destructive_tools} onChange={event => set('allow_destructive_tools', event.target.checked)} /> Allow destructive tools{production ? ' (never on production)' : ''}</label>
        </div>

        {problems.length > 0 && target && <ul className="text-[11px] text-orange-300 list-disc pl-5">{problems.map(problem => <li key={problem}>{problem}</li>)}</ul>}
        <div className="flex gap-3">
          <button type="button" data-testid="launch" className={primaryButtonClass} disabled={!target || problems.length > 0 || submitting} onClick={launch}>{submitting ? 'Launching…' : 'Launch campaign'}</button>
          <Link to="/campaigns" className={buttonClass}>Cancel</Link>
        </div>
      </section>
    </main>
  )
}
