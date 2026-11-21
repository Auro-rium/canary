import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { buttonClass, ErrorNotice, Field, inputClass, Notice, PageHeader, primaryButtonClass, StatusBadge } from '../components/Console'
import { can, PERMISSION, useMe } from '../lib/useMe'
import { VerificationPanel } from '../components/TargetParts'
import { createTarget } from '../lib/api'
import { gutter, pageClass } from '../lib/presentation'
import { AUTH_TYPES, buildTargetBody, EMPTY_TARGET_FORM, validateTarget, validateTemplate, type AuthType, type TargetFormState } from '../lib/targetForm'
import type { TargetCreated } from '../lib/v2'

const STEPS = ['Endpoint', 'Authentication', 'Session & request', 'Review', 'Verify & test'] as const

function Secret({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  // Password input: the value is write-only and is never echoed back by the API.
  return <Field label={label} hint="Stored encrypted; never shown again."><input type="password" autoComplete="new-password" aria-label={label} className={inputClass} value={value} onChange={event => onChange(event.target.value)} /></Field>
}

export default function TargetNewPage() {
  const { me } = useMe()
  const [step, setStep] = useState(0)
  const [form, setForm] = useState<TargetFormState>(EMPTY_TARGET_FORM)
  const [created, setCreated] = useState<TargetCreated | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [verified, setVerified] = useState(false)

  const set = <K extends keyof TargetFormState>(key: K, value: TargetFormState[K]) => setForm(previous => ({ ...previous, [key]: value }))
  const text = (key: keyof TargetFormState, label: string, extra?: { placeholder?: string; hint?: string }): ReactNode => (
    <Field label={label} hint={extra?.hint}><input aria-label={label} className={inputClass} placeholder={extra?.placeholder} value={String(form[key])} onChange={event => set(key, event.target.value as never)} /></Field>
  )

  const problems = validateTarget(form)
  const templateProblem = validateTemplate(form.requestTemplate)

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      setCreated(await createTarget(buildTargetBody(form)))
      // Clear every secret from memory once the server has it.
      setForm(previous => ({ ...previous, token: '', headerValue: '', clientSecret: '', password: '' }))
      setStep(4)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (me && !can(me, PERMISSION.targetsWrite)) {
    return <main className={pageClass}><PageHeader eyebrow="Onboarding" title="Add target" /><section className={`${gutter} py-8`}><Notice>Your role ({me.role}) cannot register targets.</Notice></section></main>
  }

  return (
    <main className={pageClass}>
      <PageHeader eyebrow="Onboarding" title="Add target" />
      <section className={`${gutter} py-8 max-w-3xl space-y-6`}>
        <ol className="flex flex-wrap gap-2 text-[10px] uppercase tracking-wider" aria-label="Wizard steps">
          {STEPS.map((label, index) => <li key={label} aria-current={index === step ? 'step' : undefined} className={`border px-2 py-1 ${index === step ? 'border-white text-white' : 'border-white/15 text-white/60'}`}>{index + 1}. {label}</li>)}
        </ol>
        {error && <ErrorNotice message={error} />}

        {step === 0 && (
          <div className="space-y-4">
            {text('name', 'Name', { placeholder: 'support-agent (staging)' })}
            {text('endpoint', 'Endpoint URL', { placeholder: 'https://agent.example.com/chat', hint: 'Only agents you own. Private and loopback addresses are refused.' })}
            <Field label="Environment" hint="Production targets are limited to conservative, safe campaign settings.">
              <select aria-label="Environment" className={inputClass} value={form.environment} onChange={event => set('environment', event.target.value as TargetFormState['environment'])}><option value="staging">Staging</option><option value="production">Production</option></select>
            </Field>
          </div>
        )}

        {step === 1 && (
          <div className="space-y-4">
            <Field label="Auth type">
              <select aria-label="Auth type" className={inputClass} value={form.authType} onChange={event => set('authType', event.target.value as AuthType)}>{AUTH_TYPES.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select>
            </Field>
            {form.authType === 'bearer' && <Secret label="Bearer token" value={form.token} onChange={value => set('token', value)} />}
            {form.authType === 'header' && <>{text('headerName', 'Header name', { placeholder: 'X-Api-Key' })}<Secret label="Header value" value={form.headerValue} onChange={value => set('headerValue', value)} /></>}
            {form.authType === 'oauth_client_credentials' && <>{text('tokenUrl', 'Token URL')}{text('clientId', 'Client ID')}<Secret label="Client secret" value={form.clientSecret} onChange={value => set('clientSecret', value)} />{text('scope', 'Scope (optional)')}{text('audience', 'Audience (optional)')}</>}
            {form.authType === 'cookie_login' && <>{text('loginUrl', 'Login URL')}{text('username', 'Username')}<Secret label="Password" value={form.password} onChange={value => set('password', value)} />{text('usernameField', 'Username field')}{text('passwordField', 'Password field')}</>}
          </div>
        )}

        {step === 2 && (
          <div className="space-y-4">
            <Field label="Session mode" hint="stateless_history: the full history is sent every turn. server_session: the target keeps the thread. cookie: the target sets a session cookie.">
              <select aria-label="Session mode" className={inputClass} value={form.sessionMode} onChange={event => set('sessionMode', event.target.value as TargetFormState['sessionMode'])}><option value="stateless_history">Stateless (send history)</option><option value="server_session">Server session</option><option value="cookie">Cookie session</option></select>
            </Field>
            {form.sessionMode === 'server_session' && text('sessionIdPath', 'Session id path', { placeholder: 'thread_id', hint: 'Dot path to the session id in the response.' })}
            <Field label="Request template (JSON)" hint='Use "{{MESSAGE}}" once, optionally "{{SESSION_ID}}" and "{{HISTORY}}", each as a whole quoted value.'>
              <textarea aria-label="Request template" rows={5} className={`${inputClass} font-mono`} value={form.requestTemplate} onChange={event => set('requestTemplate', event.target.value)} />
            </Field>
            {templateProblem && <p className="text-[11px] text-orange-300">{templateProblem}</p>}
            {text('responsePath', 'Response path', { placeholder: 'choices.0.message.content', hint: 'Dot path to the reply text. Leave empty if the body is the reply.' })}
            {text('toolTracePath', 'Tool trace path (optional)')}
          </div>
        )}

        {step === 3 && (
          <div className="space-y-3 text-xs">
            <dl className="grid grid-cols-[10rem_1fr] gap-y-1">
              <dt className="text-white/60">Name</dt><dd>{form.name}</dd>
              <dt className="text-white/60">Endpoint</dt><dd className="break-all">{form.endpoint}</dd>
              <dt className="text-white/60">Environment</dt><dd>{form.environment}</dd>
              <dt className="text-white/60">Auth</dt><dd>{form.authType} (secret hidden)</dd>
              <dt className="text-white/60">Session</dt><dd>{form.sessionMode}</dd>
              <dt className="text-white/60">Response path</dt><dd>{form.responsePath || '(whole body)'}</dd>
            </dl>
            {problems.length > 0 && <ul className="text-[11px] text-orange-300 list-disc pl-5">{problems.map(problem => <li key={problem}>{problem}</li>)}</ul>}
          </div>
        )}

        {step === 4 && created && (
          <div className="space-y-8">
            <p className="text-xs">Registered <strong>{created.target.name}</strong> <StatusBadge status={verified ? 'verified' : 'unverified'} /></p>
            <VerificationPanel targetId={created.target.target_id} instructions={created.verification} onVerified={() => setVerified(true)} />
            <div className="flex gap-3">
              {verified && <Link data-testid="goto-campaign" to={`/campaigns/new?target=${created.target.target_id}`} className={primaryButtonClass}>Run a campaign</Link>}
              <Link to="/targets" className={buttonClass}>All targets</Link>
            </div>
          </div>
        )}

        {step < 4 && (
          <div className="flex gap-3">
            <button type="button" className={buttonClass} disabled={step === 0} onClick={() => setStep(step - 1)}>Back</button>
            {step < 3 && <button type="button" className={primaryButtonClass} onClick={() => setStep(step + 1)}>Next</button>}
            {step === 3 && <button type="button" data-testid="create-target" className={primaryButtonClass} disabled={busy || problems.length > 0} onClick={submit}>{busy ? 'Registering…' : 'Register target'}</button>}
          </div>
        )}
      </section>
    </main>
  )
}
