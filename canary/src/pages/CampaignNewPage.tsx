import { useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ErrorNotice, PageHeader } from '../components/Console'
import { runCampaignSSE } from '../lib/api'
import { pageClass } from '../lib/presentation'
import { TECHNIQUES } from '../lib/techniques'
import type { SseEvent } from '../lib/types'

const campaignId = () => `RX-${crypto.randomUUID().slice(0, 8).toUpperCase()}`

export default function CampaignNewPage() {
  const navigate = useNavigate(); const abortRef = useRef<AbortController | null>(null)
  const [target, setTarget] = useState(''); const [techniques, setTechniques] = useState<string[]>([])
  const [headers, setHeaders] = useState(''); const [template, setTemplate] = useState(''); const [responsePath, setResponsePath] = useState('')
  const [advanced, setAdvanced] = useState(false); const [running, setRunning] = useState(false); const [logs, setLogs] = useState<string[]>([]); const [error, setError] = useState<string | null>(null)
  const validCount = useMemo(() => techniques.length, [techniques])
  const toggle = (id: string) => setTechniques(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id])
  const start = async () => {
    let parsedHeaders: Record<string, string> | undefined
    try { const url = new URL(target.trim()); if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Target URL must use HTTP or HTTPS.'); if (headers.trim()) { const value: unknown = JSON.parse(headers); if (!value || Array.isArray(value) || Object.values(value as Record<string, unknown>).some(entry => typeof entry !== 'string')) throw new Error('Headers must be a JSON object with string values.'); parsedHeaders = value as Record<string, string> } if (template.trim()) JSON.parse(template) } catch (error) { setError(error instanceof Error ? error.message : 'Invalid target configuration.'); return }
    if (!techniques.length) { setError('Select at least one attack strategy.'); return }
    setError(null); setLogs([]); setRunning(true); const controller = new AbortController(); abortRef.current = controller
    try { await runCampaignSSE({ campaign_id: campaignId(), target_url: target.trim(), techniques, headers: parsedHeaders, request_template: template.trim() || undefined, response_path: responsePath.trim() || undefined }, (event: SseEvent) => {
      if (event.type === 'log') setLogs(current => [...current, `[${event.payload.level}] ${event.payload.message}`])
      if (event.type === 'campaign_complete') { setHeaders(''); navigate(`/campaigns/${event.payload.run_id}`) }
      if (event.type === 'campaign_failed') setError(event.payload.message)
    }, controller.signal) } catch (error) { if (!controller.signal.aborted) setError(error instanceof Error ? error.message : 'Campaign request failed.') } finally { setRunning(false); abortRef.current = null }
  }
  return <main className={pageClass}><PageHeader eyebrow="Authorized target configuration" title="Run audit" />
    <section className="max-w-6xl mx-auto px-6 sm:px-10 py-10 grid lg:grid-cols-2 gap-10"><div><label className="block text-[10px] uppercase tracking-wider text-white/45">HTTP target endpoint<input value={target} disabled={running} onChange={event => setTarget(event.target.value)} placeholder="https://your-agent.example/chat" className="mt-2 w-full bg-white/[0.03] border border-white/20 px-3 py-3 text-sm text-white outline-none focus:border-red-500" /></label><p className="mt-2 text-[10px] text-white/35">Use only targets you are authorized to assess.</p>
      <button onClick={() => setAdvanced(value => !value)} className="mt-6 border border-white/20 px-3 py-2 text-[10px] uppercase tracking-wider">{advanced ? 'Hide' : 'Show'} advanced target config</button>{advanced && <div className="mt-4 space-y-4"><label className="block text-[10px] uppercase tracking-wider text-white/45">Headers (JSON)<textarea value={headers} disabled={running} onChange={event => setHeaders(event.target.value)} rows={4} placeholder={'{"Authorization":"Bearer …"}'} className="mt-2 w-full bg-white/[0.03] border border-white/20 p-3 text-xs text-white outline-none" /></label><p className="text-[10px] text-yellow-300/80">Headers are used for this run only, may enter server checkpoints, and are never displayed after launch.</p><label className="block text-[10px] uppercase tracking-wider text-white/45">Request template (JSON)<textarea value={template} disabled={running} onChange={event => setTemplate(event.target.value)} rows={4} placeholder={'{"messages":[{"role":"user","content":"{{PROMPT}}"}]}'} className="mt-2 w-full bg-white/[0.03] border border-white/20 p-3 text-xs text-white outline-none" /></label><label className="block text-[10px] uppercase tracking-wider text-white/45">Response path<input value={responsePath} disabled={running} onChange={event => setResponsePath(event.target.value)} placeholder="choices.0.message.content" className="mt-2 w-full bg-white/[0.03] border border-white/20 px-3 py-3 text-sm text-white outline-none" /></label></div>}</div>
      <div><div className="flex justify-between items-center"><h2 className="text-xs uppercase tracking-[0.18em]">Strategies</h2><button disabled={running} onClick={() => setTechniques(TECHNIQUES.map(item => item.id))} className="text-[10px] text-white/50 underline">Select all</button></div><div className="mt-4 grid sm:grid-cols-2 gap-3">{TECHNIQUES.map(item => <button type="button" key={item.id} disabled={running} onClick={() => toggle(item.id)} className={`text-left border p-4 transition-colors ${techniques.includes(item.id) ? 'border-red-500 bg-red-950/20' : 'border-white/15 hover:border-white/40'}`}><span className="text-red-400 text-[10px]">{item.asiCode}</span><h3 className="mt-2 text-xs uppercase tracking-wide">{item.name}</h3><p className="mt-2 text-[10px] leading-relaxed text-white/45">{item.description}</p></button>)}</div><button disabled={running || !target.trim() || !validCount} onClick={start} className="mt-6 w-full bg-red-600 py-4 text-xs uppercase tracking-[0.2em] disabled:opacity-30">{running ? `Executing ${validCount} strategies…` : `Run ${validCount} strategy audit`}</button></div>
      <div className="lg:col-span-2">{error && <ErrorNotice message={error} />}{logs.length > 0 && <div className="mt-5 border border-white/10 bg-white/[0.02] max-h-64 overflow-auto p-4"><div className="text-[10px] uppercase tracking-wider text-white/35 mb-3">Live execution log</div>{logs.map((log, index) => <div key={`${log}-${index}`} className="py-1 text-[10px] text-white/65">{log}</div>)}</div>}</div>
    </section>
  </main>
}
