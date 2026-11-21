import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Card, Notice, Page, PageHeader } from '../components/Console'
import { Stepper } from '../components/Stepper'
import { VerificationPanel } from '../components/TargetParts'
import { ErrorState, Field, StatusBadge, buttonClass, inputClass, primaryButtonClass, useToast } from '../components/ui'
import { createTarget } from '../lib/api'
import { AUTH_TYPES, buildTargetBody, EMPTY_TARGET_FORM, validateTarget, validateTemplate, type AuthType, type TargetFormState } from '../lib/targetForm'
import { can, PERMISSION, useMe } from '../lib/useMe'
import type { TargetCreated } from '../lib/v2'

const STEPS = ['Endpoint', 'Authentication', 'Session mode', 'Template & response', 'Review', 'Verify'] as const
const REVIEW = 4
const VERIFY = 5

function Secret({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  // Password input: the value is write-only and is never echoed back by the API.
  return <Field label={label} hint="Stored encrypted; never shown again."><input type="password" autoComplete="new-password" className={inputClass} value={value} onChange={event => onChange(event.target.value)} /></Field>
}

export default function TargetNewPage() {
  const { me } = useMe()
  const toast = useToast()
  const [step, setStep] = useState(0)
  const [form, setForm] = useState<TargetFormState>(EMPTY_TARGET_FORM)
  const [created, setCreated] = useState<TargetCreated | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [verified, setVerified] = useState(false)
  const heading = useRef<HTMLHeadingElement>(null)
  // Keyboard and screen-reader users land on the new step's heading after Next/Back.
  useEffect(() => { if (step > 0) heading.current?.focus() }, [step])

  const set = <K extends keyof TargetFormState>(key: K, value: TargetFormState[K]) => setForm(previous => ({ ...previous, [key]: value }))
  const text = (key: keyof TargetFormState, label: string, extra?: { placeholder?: string; hint?: string }): ReactNode => (
    <Field label={label} hint={extra?.hint}><input className={inputClass} placeholder={extra?.placeholder} value={String(form[key])} onChange={event => set(key, event.target.value as never)} /></Field>
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
      setStep(VERIFY)
      toast({ title: 'Target registered', description: 'Now verify ownership to unlock campaigns.', tone: 'ok' })
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (me && !can(me, PERMISSION.targetsWrite)) {
    return <Page><PageHeader title="Add target" /><Notice>Your role ({me.role}) cannot register targets.</Notice></Page>
  }

  const nextDisabled = (step === 0 && (!form.name.trim() || !form.endpoint.trim())) || (step === 3 && templateProblem !== null)

  return (
    <Page>
      <PageHeader eyebrow="Onboarding" title="Add target" />
      <div className="max-w-3xl space-y-5">
        <Stepper steps={STEPS} current={step} />
        {error && <ErrorState title="Could not register the target" message={error} />}
        <Card className="space-y-4">
          <h2 ref={heading} tabIndex={-1} className="text-lg font-semibold outline-none">{step + 1}. {STEPS[step]}</h2>

          {step === 0 && (
            <div className="space-y-4">
              {text('name', 'Name', { placeholder: 'support-agent (staging)' })}
              {text('endpoint', 'Endpoint URL', { placeholder: 'https://agent.example.com/chat', hint: 'Only agents you own. Private and loopback addresses are refused.' })}
              <Field label="Environment" hint="Production targets are limited to conservative, safe campaign settings.">
                <select className={inputClass} value={form.environment} onChange={event => set('environment', event.target.value as TargetFormState['environment'])}><option value="staging">Staging</option><option value="production">Production</option></select>
              </Field>
            </div>
          )}

          {step === 1 && (
            <div className="space-y-4">
              <Field label="Auth type">
                <select className={inputClass} value={form.authType} onChange={event => set('authType', event.target.value as AuthType)}>{AUTH_TYPES.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select>
              </Field>
              {form.authType === 'none' && <p className="text-muted">No credentials are sent to the target.</p>}
              {form.authType === 'bearer' && <Secret label="Bearer token" value={form.token} onChange={value => set('token', value)} />}
              {form.authType === 'header' && <>{text('headerName', 'Header name', { placeholder: 'X-Api-Key' })}<Secret label="Header value" value={form.headerValue} onChange={value => set('headerValue', value)} /></>}
              {form.authType === 'oauth_client_credentials' && <>{text('tokenUrl', 'Token URL')}{text('clientId', 'Client ID')}<Secret label="Client secret" value={form.clientSecret} onChange={value => set('clientSecret', value)} />{text('scope', 'Scope (optional)')}{text('audience', 'Audience (optional)')}</>}
              {form.authType === 'cookie_login' && <>{text('loginUrl', 'Login URL')}{text('username', 'Username')}<Secret label="Password" value={form.password} onChange={value => set('password', value)} />{text('usernameField', 'Username field')}{text('passwordField', 'Password field')}</>}
            </div>
          )}

          {step === 2 && (
            <div className="space-y-4">
              <Field label="Session mode" hint="stateless_history: the full history is sent every turn. server_session: the target keeps the thread. cookie: the target sets a session cookie.">
                <select className={inputClass} value={form.sessionMode} onChange={event => set('sessionMode', event.target.value as TargetFormState['sessionMode'])}><option value="stateless_history">Stateless (send history)</option><option value="server_session">Server session</option><option value="cookie">Cookie session</option></select>
              </Field>
              {form.sessionMode === 'server_session' && text('sessionIdPath', 'Session id path', { placeholder: 'thread_id', hint: 'Dot path to the session id in the response.' })}
            </div>
          )}

          {step === 3 && (
            <div className="space-y-4">
              <Field label="Request template (JSON)" hint='Use "{{MESSAGE}}" once, optionally "{{SESSION_ID}}" and "{{HISTORY}}", each as a whole quoted value.'>
                <textarea rows={5} className={`${inputClass} font-mono text-xs`} value={form.requestTemplate} onChange={event => set('requestTemplate', event.target.value)} />
              </Field>
              {templateProblem && <p role="alert" className="text-warn"><span aria-hidden="true">! </span>{templateProblem}</p>}
              {text('responsePath', 'Response path', { placeholder: 'choices.0.message.content', hint: 'Dot path to the reply text. Leave empty if the body is the reply.' })}
              {text('toolTracePath', 'Tool trace path (optional)')}
            </div>
          )}

          {step === REVIEW && (
            <div className="space-y-3">
              <dl className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[10rem_1fr]">
                <dt className="text-muted">Name</dt><dd>{form.name}</dd>
                <dt className="text-muted">Endpoint</dt><dd className="break-all font-mono text-xs">{form.endpoint}</dd>
                <dt className="text-muted">Environment</dt><dd>{form.environment}</dd>
                <dt className="text-muted">Auth</dt><dd>{form.authType} (secret hidden)</dd>
                <dt className="text-muted">Session</dt><dd>{form.sessionMode}</dd>
                <dt className="text-muted">Response path</dt><dd className="font-mono text-xs">{form.responsePath || '(whole body)'}</dd>
              </dl>
              <p className="text-xs text-muted">Registering stores the target (secrets encrypted). The next step checks that Canary can reach the endpoint and proves you own it.</p>
              {problems.length > 0 && <div role="alert"><ul className="list-disc space-y-0.5 pl-5 text-warn">{problems.map(problem => <li key={problem}>{problem}</li>)}</ul></div>}
            </div>
          )}

          {step === VERIFY && created && (
            <div className="space-y-6">
              <p>Registered <strong>{created.target.name}</strong> <StatusBadge status={verified ? 'verified' : 'unverified'} /></p>
              <VerificationPanel targetId={created.target.target_id} instructions={created.verification} onVerified={() => setVerified(true)} />
              <div className="flex flex-wrap gap-3">
                {verified && <Link data-testid="goto-campaign" to={`/campaigns/new?target=${created.target.target_id}`} className={primaryButtonClass}>Run a campaign</Link>}
                <Link to="/targets" className={buttonClass}>All targets</Link>
              </div>
            </div>
          )}

          {step < VERIFY && (
            <div className="flex gap-3 border-t border-line pt-4">
              <button type="button" className={buttonClass} disabled={step === 0} onClick={() => setStep(step - 1)}>Back</button>
              {step < REVIEW && <button type="button" className={primaryButtonClass} disabled={nextDisabled} onClick={() => setStep(step + 1)}>Next</button>}
              {step === REVIEW && <button type="button" data-testid="create-target" className={primaryButtonClass} disabled={busy || problems.length > 0} onClick={submit}>{busy ? 'Registering…' : 'Register target'}</button>}
            </div>
          )}
        </Card>
      </div>
    </Page>
  )
}
