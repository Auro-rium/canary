import { useState } from 'react'
import { ApiError, testTargetConnection, verifyTarget } from '../lib/api'
import type { TargetView, TestConnectionResult, VerificationInstructions, VerifyMethod } from '../lib/v2'
import { buttonClass, ErrorNotice, Notice } from './Console'

const METHODS: { id: VerifyMethod; title: string; blurb: string }[] = [
  { id: 'http_wellknown', title: 'Well-known file', blurb: 'Serve the token as plain text at this URL on the target host.' },
  { id: 'dns_txt', title: 'DNS TXT record', blurb: 'Publish a TXT record on the target host name.' },
  { id: 'response_header', title: 'Response header', blurb: 'Make the target echo this header (with this value) on its responses.' },
]

function describe(method: VerifyMethod, instructions: VerificationInstructions | null): string {
  if (!instructions) return 'The token was shown once when the target was registered. Register again to get a new one.'
  if (method === 'http_wellknown') return `GET ${instructions.http_wellknown.url}  ->  body: ${instructions.http_wellknown.content}`
  if (method === 'dns_txt') return `${instructions.dns_txt.type} ${instructions.dns_txt.name}  =  ${instructions.dns_txt.value}`
  return `${instructions.response_header.header}: ${instructions.response_header.value}`
}

/** The three ownership-verification methods with a "check now" button each. */
export function VerificationPanel({
  targetId, instructions, onVerified,
}: { targetId: string; instructions: VerificationInstructions | null; onVerified: (target: TargetView) => void }) {
  const [busy, setBusy] = useState<VerifyMethod | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const check = async (method: VerifyMethod) => {
    setBusy(method)
    setMessage(null)
    setError(null)
    try {
      const result = await verifyTarget(targetId, method)
      if (result.verified) onVerified(result.target)
      else setMessage(`Not verified yet: ${result.reason}`)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <section aria-label="Ownership verification" className="space-y-3">
      <p className="text-xs text-white/60">Prove you own this target by completing <strong>one</strong> of the methods below, then press Check. Campaigns are refused until a target is verified.</p>
      {METHODS.map(method => (
        <div key={method.id} data-testid={`verify-${method.id}`} className="border border-white/10 p-3">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-[11px] uppercase tracking-wider">{method.title}</h3>
            <button type="button" className={buttonClass} disabled={busy !== null} onClick={() => check(method.id)}>{busy === method.id ? 'Checking…' : 'Check'}</button>
          </div>
          <p className="mt-1 text-[10px] text-white/40">{method.blurb}</p>
          <pre className="mt-2 text-[11px] bg-white/[0.05] p-2 overflow-x-auto whitespace-pre-wrap break-all">{describe(method.id, instructions)}</pre>
        </div>
      ))}
      {message && <Notice>{message}</Notice>}
      {error && <ErrorNotice message={error} />}
    </section>
  )
}

/** Sends one benign hello through the backend and shows the parsed reply. */
export function TestConnection({ targetId }: { targetId: string }) {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<TestConnectionResult | null>(null)
  const [unsupported, setUnsupported] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = async () => {
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      setResult(await testTargetConnection(targetId))
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 405 || e.status === 501)) setUnsupported(true)
      else setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section aria-label="Test connection" className="space-y-3">
      <button type="button" data-testid="test-connection" className={buttonClass} disabled={busy} onClick={run}>{busy ? 'Sending hello…' : 'Test connection'}</button>
      <p className="text-[10px] text-white/40">Sends one benign greeting and shows how the reply is parsed with your response path.</p>
      {unsupported && <div data-testid="test-unsupported"><Notice>Requires backend support: this server has no <code>POST /api/v2/targets/{'{id}'}/test</code> endpoint yet.</Notice></div>}
      {error && <ErrorNotice message={error} />}
      {result && (
        <div data-testid="test-result" className={`border p-3 text-xs ${result.ok ? 'border-emerald-600/40' : 'border-red-600/40'}`}>
          <p className="text-[10px] uppercase tracking-wider text-white/40">{result.ok ? 'Reachable' : 'Failed'}{result.http_status ? ` · HTTP ${result.http_status}` : ''} · {Math.round(result.latency_ms)}ms</p>
          {result.reply_text !== null && <p className="mt-2 whitespace-pre-wrap break-words">Parsed reply: <span className="text-white">{result.reply_text || '(empty)'}</span></p>}
          {result.error && <p className="mt-2 text-red-300">{result.error}</p>}
        </div>
      )}
    </section>
  )
}
