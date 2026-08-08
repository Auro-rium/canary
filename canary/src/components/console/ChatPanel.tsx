import React, { useState, useRef, useEffect, useCallback } from 'react'
import { useConsoleStore, type ChatMessage } from '../../store/useConsoleStore'
import { parseCommand, HELP_TEXT } from '../../lib/commands'
import { saveRun } from '../../lib/db'
import * as api from '../../lib/api'
import { ApiError } from '../../lib/api'
import type { AgentStatus, LogEntry, FindingPayload, CompletePayload, FailedPayload, SSEEvent } from '../../lib/types'

function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message
  if (e instanceof Error) return e.message
  return 'Unknown error'
}

const KIND_CLASS: Record<ChatMessage['kind'], string> = {
  text:    'text-white/70',
  log:     'text-white/40',
  finding: 'text-red-400',
  report:  'text-white',
  error:   'text-red-500',
  help:    'text-white/50 whitespace-pre-wrap',
  list:    'text-white/60 whitespace-pre-wrap',
}

export default function ChatPanel() {
  const store = useConsoleStore()
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [store.chatMessages])

  const say = useCallback(
    (kind: ChatMessage['kind'], content: string) => store.pushMessage({ role: 'system', kind, content }),
    [store],
  )

  const runCampaign = useCallback(async (targetUrl: string, techniques: string[]) => {
    if (!targetUrl.trim()) {
      say('error', 'No target set. Use: connect <url>')
      return
    }
    if (techniques.length === 0) {
      say('error', 'No valid techniques given. Type "help" to see the list.')
      return
    }

    store.resetCampaign()
    store.setTargetUrl(targetUrl)
    store.setTechniques(techniques)
    store.setLastConfig({ targetUrl, techniques })
    store.setPhase('running')
    say('text', `Campaign ${store.campaignId} started — ${techniques.length} technique(s) against ${targetUrl}`)

    const onEvent = (event: SSEEvent) => {
      if (event.type === 'agent_state') {
        const p = event.payload as { agent_id: string; status: AgentStatus; active_edge?: string }
        store.updateAgent(p.agent_id, p.status)
        if (p.active_edge) store.fireEdge(p.active_edge)
      }
      if (event.type === 'log') {
        const p = event.payload as { level: LogEntry['level']; message: string }
        store.appendLog(p.level, p.message)
        say('log', `[${p.level}] ${p.message}`)
      }
      if (event.type === 'finding') {
        const f = event.payload as FindingPayload
        store.addFinding(f)
        say('finding', `${f.severity}: ${f.asi_code} — ${f.verdict} (${f.technique_id})`)
      }
      if (event.type === 'campaign_complete') {
        const payload = event.payload as CompletePayload
        store.setReport(payload)
        store.setPhase('complete')
        store.addRunHistory(payload)
        saveRun(payload).catch(() => { /* IndexedDB unavailable — history just won't persist */ })
        say(
          'report',
          `Campaign complete — ${payload.total_findings} finding(s) ` +
          `(${payload.critical_count} critical, ${payload.high_count} high), ${payload.duration_seconds}s`,
        )
      }
      if (event.type === 'campaign_failed') {
        const payload = event.payload as FailedPayload
        store.setPhase('failed')
        say('error', payload.message)
      }
    }

    try {
      await api.runCampaignSSE(
        { campaign_id: store.campaignId, target_url: targetUrl.trim(), techniques },
        onEvent,
      )
    } catch (e) {
      say('error', `Campaign failed: ${errorMessage(e)}`)
      store.setPhase('idle')
    }
  }, [store, say])

  const runCommand = useCallback(async (raw: string) => {
    const cmd = parseCommand(raw)

    switch (cmd.type) {
      case 'CONNECT':
        store.setTargetUrl(cmd.url)
        say('text', `Target set to ${cmd.url}`)
        return

      case 'RUN':
        if (cmd.invalid.length) say('error', `Unknown technique(s): ${cmd.invalid.join(', ')}`)
        await runCampaign(store.targetUrl, cmd.techniques)
        return

      case 'RERUN_LAST':
        if (!store.lastConfig) {
          say('error', 'No previous campaign to re-run.')
          return
        }
        await runCampaign(store.lastConfig.targetUrl, store.lastConfig.techniques)
        return

      case 'SHOW_FINDINGS':
        try {
          const data = await api.getFindings('page=1&page_size=50')
          say('list', JSON.stringify(data, null, 2))
        } catch (e) { say('error', errorMessage(e)) }
        return

      case 'SHOW_INCIDENTS':
        try {
          const data = await api.getIncidents()
          say('list', JSON.stringify(data, null, 2))
        } catch (e) { say('error', errorMessage(e)) }
        return

      case 'SHOW_COVERAGE':
        try {
          const data = await api.getTargetCoverage(cmd.targetId)
          say('list', JSON.stringify(data, null, 2))
        } catch (e) { say('error', errorMessage(e)) }
        return

      case 'SHOW_TRENDS':
        try {
          const data = await api.getTargetTrends(cmd.targetId)
          say('list', JSON.stringify(data, null, 2))
        } catch (e) { say('error', errorMessage(e)) }
        return

      case 'SHOW_RUN':
        try {
          const data = await api.getRun(cmd.runId)
          say('list', JSON.stringify(data, null, 2))
        } catch (e) { say('error', errorMessage(e)) }
        return

      case 'EXPORT': {
        if (!store.report) {
          say('error', 'No completed campaign report to export.')
          return
        }
        const blob = new Blob([JSON.stringify(store.report, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${store.report.campaign_id}.json`
        a.click()
        URL.revokeObjectURL(url)
        say('text', `Exported ${store.report.campaign_id}.json`)
        return
      }

      case 'HELP':
        say('help', HELP_TEXT)
        return

      case 'UNKNOWN':
        say('error', `Unrecognized command: "${cmd.raw}". Type "help" for the command list.`)
        return
    }
  }, [store, say, runCampaign])

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    const raw = input.trim()
    if (!raw || busy) return
    store.pushMessage({ role: 'user', kind: 'text', content: raw })
    setInput('')
    setBusy(true)
    try {
      await runCommand(raw)
    } finally {
      setBusy(false)
    }
  }, [input, busy, store, runCommand])

  return (
    <div className="flex flex-col h-full border-x border-white/10">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 shrink-0">
        <span className="text-white/40 text-[10px] uppercase tracking-wider">Console</span>
        <div className="flex items-center gap-2">
          <span className="text-white/25 text-[9px]">[{store.chatMessages.length}]</span>
          {store.phase === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse-red" />}
          <span className="text-white/30 text-[10px]">
            {store.phase === 'running' ? 'LIVE' : store.phase === 'complete' ? 'DONE' : store.phase === 'failed' ? 'FAILED' : 'IDLE'}
          </span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-4 py-3 flex flex-col gap-2">
        {store.chatMessages.length === 0 && (
          <div className="text-white/20 text-[10px] uppercase tracking-[0.2em] py-8 text-center">
            Type &quot;help&quot; to see available commands
          </div>
        )}
        {store.chatMessages.map((m) => (
          <div key={m.id} className="flex gap-2 items-start text-[11px] font-mono leading-relaxed">
            <span className={`shrink-0 uppercase text-[9px] tracking-wider mt-0.5 ${m.role === 'user' ? 'text-white' : 'text-white/25'}`}>
              {m.role === 'user' ? '>' : '#'}
            </span>
            <span className={KIND_CLASS[m.kind]}>{m.content}</span>
          </div>
        ))}
        {busy && <span className="text-red-500 animate-blink text-[10px]">█</span>}
        <div ref={endRef} />
      </div>

      <form onSubmit={handleSubmit} className="border-t border-white/10 flex items-center shrink-0">
        <span className="px-3 text-white/30 text-xs">$</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="connect <url> · run all · show findings · help"
          className="flex-1 bg-transparent px-2 py-3 text-white text-xs font-mono placeholder:text-white/20 outline-none"
          disabled={busy}
        />
        <button
          type="submit"
          disabled={busy || !input.trim()}
          className="px-4 py-3 text-white/50 hover:text-white text-[10px] uppercase tracking-wider disabled:opacity-30 transition-colors"
        >
          Send
        </button>
      </form>
    </div>
  )
}
