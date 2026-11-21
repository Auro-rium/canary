import { describe, expect, it } from 'vitest'
import type { SseEvent } from './contracts'
import { SSE_EVENT_TYPES } from './contracts'
import { emptyCampaign, reduceEvent } from './liveState'
import { applySafeDefaults, defaultPolicy, validatePolicy } from './safeDefaults'
import { SseParser, followEvents } from './sse'

const frame = (seq: number, type: string, payload: object) =>
  `id: ${seq}\ndata: ${JSON.stringify({ type, payload, timestamp: '2026-01-01T00:00:00Z', seq })}\n\n`

function streamOf(...chunks: string[]): Response {
  const enc = new TextEncoder()
  return new Response(new ReadableStream({
    start(c) { chunks.forEach(x => c.enqueue(enc.encode(x))); c.close() },
  }), { status: 200 })
}

describe('SseParser', () => {
  it('handles frames split across chunks and comments', () => {
    const p = new SseParser()
    expect(p.push(': ping\nid: 4\ndata: {"a"')).toEqual([])
    expect(p.push(':1}\n\n')).toEqual([{ id: '4', event: undefined, data: '{"a":1}' }])
  })
})

describe('followEvents', () => {
  it('reconnects with Last-Event-ID and drops replayed seqs', async () => {
    const seen: number[] = []
    const requests: Array<Record<string, string>> = []
    const bodies = [
      streamOf(frame(1, 'campaign_started', { total_conversations: 1 }), frame(2, 'budget_update', {})),
      streamOf(frame(2, 'budget_update', {}), frame(3, 'campaign_complete', {})),
    ]
    const fetchImpl = (async (_url: string, init?: RequestInit) => {
      requests.push(init?.headers as Record<string, string>)
      expect(init?.credentials).toBe('include')
      return bodies.shift()!
    }) as unknown as typeof fetch
    const last = await followEvents({
      url: '/e', onEvent: e => seen.push(e.seq), fetchImpl, sleep: async () => {},
    })
    expect(seen).toEqual([1, 2, 3])
    expect(last).toBe(3)
    expect(requests[0]['Last-Event-ID']).toBeUndefined()
    expect(requests[1]['Last-Event-ID']).toBe('2')
  })

  it('resumes from a snapshot seq and stops on 401', async () => {
    const fetchImpl = (async (_u: string, init?: RequestInit) => {
      expect((init?.headers as Record<string, string> | undefined)?.['Last-Event-ID']).toBe('10')
      return new Response('{}', { status: 401 })
    }) as unknown as typeof fetch
    await expect(followEvents({ url: '/e', onEvent: () => {}, lastSeq: 10, fetchImpl, sleep: async () => {} }))
      .rejects.toMatchObject({ status: 401 })
  })

  it('gives up after maxRetries', async () => {
    const fetchImpl = (async () => new Response('', { status: 503 })) as unknown as typeof fetch
    await expect(followEvents({ url: '/e', onEvent: () => {}, fetchImpl, sleep: async () => {}, maxRetries: 2 }))
      .rejects.toThrow(/Lost the live event stream/)
  })
})

describe('reduceEvent', () => {
  const verdict = {
    conversation_id: 'c1', verdict: 'confirmed', first_failing_turn: 1, deterministic_hits: [], judge_votes: [],
    judge_agreement: 1, severity: 'high', asi_class: 'ASI01', rationale: 'r',
  }
  const payloads: Record<string, object> = {
    campaign_started: { campaign_id: 'k', total_conversations: 2 },
    conversation_started: { campaign_id: 'k', conversation_id: 'c1', technique: 'prompt-injection', trial_index: 0 },
    turn: { campaign_id: 'k', conversation_id: 'c1', index: 0, message_preview: 'hi', response_preview: 'yo', tool_call_names: [], http_status: 200, latency_ms: 5, monitor_hits: [], error: null },
    monitor_hit: { campaign_id: 'k', conversation_id: 'c1', turn_index: 0, hit: 'secret_leak', severity: 'critical', stops_conversation: true },
    conversation_finished: { campaign_id: 'k', conversation_id: 'c1', status: 'stopped_killed', turns: 1 },
    verdict: { campaign_id: 'k', verdict },
    budget_update: { campaign_id: 'k', requests_used: 3, max_total_requests: 10, llm_cost_usd: 0.1, max_llm_cost_usd: 1 },
    campaign_complete: { campaign_id: 'k', conversations: 2, confirmed: 1, technique_results: [], duration_seconds: 1 },
    campaign_failed: { campaign_id: 'k', message: 'boom' },
    campaign_cancelled: { campaign_id: 'k', reason: 'kill_switch', cancelled_by: null },
  }

  it('handles every event type in contracts', () => {
    expect(Object.keys(payloads).sort()).toEqual([...SSE_EVENT_TYPES].sort())
    let s = emptyCampaign('k')
    SSE_EVENT_TYPES.forEach((type, i) => {
      s = reduceEvent(s, { type, payload: payloads[type], timestamp: 't', seq: i + 1 } as unknown as SseEvent)
    })
    expect(s.cells.c1.status).toBe('stopped_killed')
    expect(s.cells.c1.verdict).toBe('confirmed')
    expect(s.cells.c1.hits).toHaveLength(1)
    expect(s.budget?.requests_used).toBe(3)
    expect(s.status).toBe('cancelled')
    expect(s.cancelledReason).toBe('kill_switch')
    expect(s.lastSeq).toBe(SSE_EVENT_TYPES.length)
  })

  it('ignores replayed seqs', () => {
    let s = emptyCampaign('k')
    const ev = { type: 'campaign_failed', payload: payloads.campaign_failed, timestamp: 't', seq: 5 } as unknown as SseEvent
    s = reduceEvent(s, ev)
    const again = reduceEvent(s, { ...ev, payload: { campaign_id: 'k', message: 'other' } } as SseEvent)
    expect(again).toBe(s)
  })
})

describe('safe defaults', () => {
  it('forces production limits', () => {
    const bad = { ...defaultPolicy('staging'), techniques: ['prompt-injection', 'denial-of-service'], rate_limit_rps: 5, max_parallel_conversations: 9, max_total_requests: 900, allow_destructive_tools: true }
    expect(validatePolicy(bad, 'production').length).toBeGreaterThan(3)
    const safe = applySafeDefaults(bad, 'production')
    expect(safe).toMatchObject({ rate_limit_rps: 1, max_parallel_conversations: 2, max_total_requests: 300, allow_destructive_tools: false, techniques: ['prompt-injection'] })
    expect(validatePolicy(safe, 'production')).toEqual([])
  })

  it('leaves staging alone', () => {
    const p = { ...defaultPolicy('staging'), techniques: ['denial-of-service'], max_total_requests: 500 }
    expect(applySafeDefaults(p, 'staging')).toBe(p)
    expect(validatePolicy(p, 'staging')).toEqual([])
  })
})
