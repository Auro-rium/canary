import { useState } from 'react'
import { verifyTarget } from '../lib/api'
import type { TargetView, VerificationInstructions, VerifyMethod } from '../lib/v2'
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
          <p className="mt-1 text-[10px] text-white/60">{method.blurb}</p>
          <pre className="mt-2 text-[11px] bg-white/[0.05] p-2 overflow-x-auto whitespace-pre-wrap break-all">{describe(method.id, instructions)}</pre>
        </div>
      ))}
      {message && <Notice>{message}</Notice>}
      {error && <ErrorNotice message={error} />}
    </section>
  )
}
