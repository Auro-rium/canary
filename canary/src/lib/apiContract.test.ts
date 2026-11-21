import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it, vi } from 'vitest'
import * as api from './api'
import { SseParser, followEvents, SESSION_ENDED_MESSAGE } from './sse'
import { SSE_EVENT_TYPES, type ConversationStatus } from './contracts'
import { CONVERSATION_STATUS_STYLE } from './presentation'
import { TERMINAL_STATUSES } from './liveState'
import { ROUTES } from './api-schema'

const root = fileURLToPath(new URL('../../', import.meta.url))
const spec = JSON.parse(readFileSync(`${root}../cyber-redteam-foundry/openapi/v2.json`, 'utf8'))

describe('OpenAPI contract', () => {
  it('api-schema.ts is up to date with openapi/v2.json (run `npm run gen:api`)', async () => {
    const path = `${root}scripts/gen-api-types.mjs`
    const { generate } = await import(/* @vite-ignore */ path) as { generate: () => string }
    expect(readFileSync(`${root}src/lib/api-schema.ts`, 'utf8')).toBe(generate())
  })

  it('every route the client calls exists in the contract', () => {
    for (const route of ['GET /api/v2/me', 'GET /api/v2/auth/providers', 'GET /api/v2/auth/login/{provider}', 'POST /api/v2/auth/logout',
      'GET /api/v2/targets', 'POST /api/v2/targets', 'GET /api/v2/targets/{target_id}', 'POST /api/v2/targets/{target_id}/verify',
      'GET /api/v2/campaigns', 'POST /api/v2/campaigns', 'GET /api/v2/campaigns/{campaign_id}', 'POST /api/v2/campaigns/{campaign_id}/cancel',
      'GET /api/v2/campaigns/{campaign_id}/events', 'GET /api/v2/conversations/{conversation_id}', 'GET /api/v2/findings',
      'PUT /api/v2/findings/{finding_id}/status', 'GET /api/v2/admin/kill-switch', 'POST /api/v2/admin/kill-switch',
      'GET /api/v2/reports/{campaign_id}']) {
      expect(ROUTES, route).toContain(route)
    }
  })

  it('the UI knows every conversation status the contract lists, plus the planner guardrail', () => {
    const fromSpec: string[] = spec.components.schemas.Conversation.properties.status.enum
    const known = Object.keys(CONVERSATION_STATUS_STYLE)
    for (const status of fromSpec) expect(known, status).toContain(status)
    const guardrail: ConversationStatus = 'stopped_planner_guardrail'
    expect(known).toContain(guardrail)
    expect(TERMINAL_STATUSES).toContain(guardrail)
  })

  it('handles every SSE event type the backend emits', () => {
    expect([...SSE_EVENT_TYPES]).toEqual(expect.arrayContaining(['verdict', 'budget_update', 'campaign_cancelled']))
  })
})

describe('CSRF double-submit', () => {
  afterEach(() => { vi.unstubAllGlobals(); api.setCsrfFallback(null) })

  const stub = (cookie: string) => {
    const calls: Array<{ url: string; init: RequestInit }> = []
    vi.stubGlobal('document', { cookie })
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      calls.push({ url, init })
      return new Response('{}', { status: 200 })
    })
    return calls
  }
  const header = (c: { init: RequestInit }, name: string) => (c.init.headers as Record<string, string>)[name]

  it('sends the canary_csrf cookie as X-CSRF-Token on every non-GET request, never on GET', async () => {
    const calls = stub('x=1; canary_csrf=tok%3D1')
    await api.getMe()
    await api.createCampaign({ target_id: 't', policy: { techniques: ['a'] } })
    await api.cancelCampaign('c1')
    await api.updateFindingStatus('f1', { status: 'wont_fix', rationale: 'r' })
    await api.setKillSwitch({ enabled: true, reason: 'x' })
    await api.logout()
    expect(header(calls[0], 'X-CSRF-Token')).toBeUndefined()
    for (const call of calls.slice(1)) expect(header(call, 'X-CSRF-Token'), call.url).toBe('tok=1')
    expect(calls.map(c => c.init.method ?? 'GET')).toEqual(['GET', 'POST', 'POST', 'PUT', 'POST', 'POST'])
    expect(calls.every(c => c.init.credentials === 'include')).toBe(true)
  })

  it('falls back to the token from /me when the cookie is unreadable', async () => {
    const calls = stub('')
    api.setCsrfFallback('from-me')
    await api.cancelCampaign('c1')
    expect(header(calls[0], 'X-CSRF-Token')).toBe('from-me')
  })

  it('builds the OIDC login URL and requests raw evidence only on demand', async () => {
    expect(api.loginUrl('google', '/campaigns?x=1')).toBe('/api/v2/auth/login/google?next=%2Fcampaigns%3Fx%3D1')
    const calls = stub('')
    await api.getConversation('c1')
    await api.getConversation('c1', true)
    expect(calls.map(c => c.url)).toEqual(['/api/v2/conversations/c1', '/api/v2/conversations/c1?raw=true'])
  })
})

describe('SSE error event', () => {
  it('parses `event: error` and surfaces "session ended" without retrying', async () => {
    const parser = new SseParser()
    expect(parser.push('event: error\ndata: {"detail": "session ended"}\n\n')).toEqual([
      { id: undefined, event: 'error', data: '{"detail": "session ended"}' },
    ])
    let fetches = 0
    const fetchImpl = (async () => {
      fetches += 1
      return new Response('event: error\ndata: {"detail": "session ended"}\n\n', { status: 200 })
    }) as unknown as typeof fetch
    await expect(followEvents({ url: '/e', onEvent: () => {}, fetchImpl, sleep: async () => {} }))
      .rejects.toMatchObject({ status: 401, message: SESSION_ENDED_MESSAGE })
    expect(fetches).toBe(1)
  })
})
