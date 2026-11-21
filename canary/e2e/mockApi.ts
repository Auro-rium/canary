// A stateful fake of the /api/v2 surface (Playwright route mocking; no backend). It enforces what
// WP8 enforces that the UI must satisfy: 401 until signed in, and X-CSRF-Token on every non-GET.
import type { Page, Route } from '@playwright/test'
import type { Schemas } from '../src/lib/api-schema'
import * as fx from './fixtures'

export interface MockOptions {
  role?: fx.RoleName
  extraPermissions?: string[]
  signedIn?: boolean
  killSwitchForbidden?: boolean
  /** Number of findings the list endpoint reports. */
  findingsTotal?: number
  /** Campaign camp1 is already completed, with per-technique results and no event stream. */
  completed?: boolean
}

export interface Mock {
  state: { signedIn: boolean; cancelled: boolean; kill: boolean }
  /** Every non-GET request: method, path, csrf header, parsed body. */
  writes: Array<{ method: string; path: string; csrf: string | undefined; body: unknown }>
  conversationQueries: string[]
  releaseCancel: () => void
  /** Make the quiet event stream deliver one more conversation (forces a live-state re-render). */
  pushConversation: (id: string) => void
}

const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, json: body })

export async function mockApi(page: Page, options: MockOptions = {}): Promise<Mock> {
  const role = options.role ?? 'operator'
  const total = options.findingsTotal ?? 2
  let releaseCancel = () => {}
  const pushes: string[] = []
  let wake = () => {}
  const cancelGate = new Promise<void>(resolve => { releaseCancel = resolve })
  const mock: Mock = {
    state: { signedIn: options.signedIn ?? true, cancelled: false, kill: false },
    writes: [], conversationQueries: [], releaseCancel: () => releaseCancel(),
    pushConversation: id => { pushes.push(id); wake() },
  }
  const targets = [fx.stagingTarget, fx.prodTarget, fx.unverifiedTarget]
  let eventRequests = 0
  const findings = new Map<string, ReturnType<typeof fx.finding>>()
  for (let n = 1; n <= total; n++) findings.set(`f${n}`, fx.finding(n))

  await page.route('**/api/v2/**', async route => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname.replace(/^\/api\/v2/, '')
    const method = request.method()
    if (method !== 'GET') {
      let body: unknown = null
      try { body = request.postDataJSON() } catch { /* no body */ }
      const csrf = request.headers()['x-csrf-token']
      mock.writes.push({ method, path, csrf, body })
      if (path !== '/auth/logout' && mock.state.signedIn && csrf !== fx.CSRF) return json(route, { detail: 'CSRF token missing or invalid' }, 403)
    }

    // Auth
    if (path === '/auth/providers') return json(route, { providers: ['oidc'] } satisfies { providers: string[] })
    if (path.startsWith('/auth/login/')) {
      mock.state.signedIn = true
      return route.fulfill({ status: 302, headers: { location: url.searchParams.get('next') ?? '/' } })
    }
    if (path === '/auth/logout') { mock.state.signedIn = false; return json(route, { status: 'ok' }) }
    if (!mock.state.signedIn) return json(route, { detail: 'Not authenticated' }, 401)
    if (path === '/me') return json(route, fx.me(role, options.extraPermissions))

    // Targets
    if (path === '/targets' && method === 'GET') return json(route, { items: targets })
    if (path === '/targets' && method === 'POST') {
      const body = mock.writes.at(-1)!.body as { name: string; endpoint: string; environment: 'staging' | 'production' }
      return json(route, { target: { ...fx.unverifiedTarget, name: body.name, endpoint: body.endpoint }, verification_token: 'tok-123', verification: fx.verificationInstructions }, 201)
    }
    if (/^\/targets\/[^/]+\/verify$/.test(path)) {
      const body = mock.writes.at(-1)!.body as { method: 'http_wellknown' }
      return json(route, { target: { ...fx.unverifiedTarget, verified: true, verified_method: body.method }, verified: true, method: body.method, reason: 'ok' })
    }
    const targetMatch = /^\/targets\/([^/]+)$/.exec(path)
    if (targetMatch && method === 'GET') {
      const found = targets.find(t => t.target_id === targetMatch[1])
      return found ? json(route, found) : json(route, { detail: 'Target not found' }, 404)
    }

    // Campaigns
    if (path === '/campaigns' && method === 'POST') return json(route, fx.campaignDetail({ status: 'queued' }), 201)
    if (path === '/campaigns') {
      const summary = fx.campaignDetail(options.completed ? { status: 'completed', confirmed: 4 } : {})
      return json(route, { items: [summary], total: 1, page: 1, page_size: 25 })
    }
    if (path === '/campaigns/camp1/cancel') {
      mock.state.cancelled = true
      releaseCancel()
      return json(route, { campaign_id: 'camp1', status: 'cancelling' })
    }
    if (path === '/campaigns/camp1/events') {
      eventRequests += 1
      const lastId = Number(request.headers()['last-event-id'] ?? 0)
      const body = (events: Parameters<typeof fx.sse>[0], first: number) => route.fulfill({ status: 200, contentType: 'text/event-stream', body: fx.sse(events, first) })
      if (lastId === 0) return body(fx.stage1, 1)
      if (lastId === fx.stage1.length) return body(fx.stage2, fx.stage1.length + 1)
      // Quiet until the operator cancels (keeps the campaign "running" for the Cancel button).
      let cancelled = false
      void cancelGate.then(() => { cancelled = true; wake() })
      while (!cancelled && pushes.length === 0) await new Promise<void>(resolve => { wake = resolve })
      if (!cancelled) {
        const id = pushes.shift()!
        return body([['conversation_started', { campaign_id: 'camp1', conversation_id: id, technique: 'prompt-injection', trial_index: Number(id.slice(1)) }]], lastId + 1)
      }
      return body(fx.cancelledEvent, lastId + 1)
    }
    if (path === '/campaigns/camp1') {
      if (options.completed) return json(route, fx.campaignDetail({ status: 'completed', confirmed: 4, technique_results: fx.techniqueResults, finished_at: '2026-01-01T00:10:00Z' }))
      return json(route, fx.campaignDetail({ status: mock.state.cancelled ? 'cancelled' : 'running' }))
    }
    void eventRequests

    // Conversations
    if (path === '/conversations/c1') {
      mock.conversationQueries.push(url.search)
      if (url.searchParams.get('raw') === 'true' && !fx.me(role, options.extraPermissions).permissions.includes('evidence:read_raw')) {
        return json(route, { detail: 'evidence:read_raw required' }, 403)
      }
      return json(route, fx.conversation(url.searchParams.get('raw') === 'true'))
    }

    // Findings
    if (path === '/findings') {
      const pageNo = Number(url.searchParams.get('page') ?? 1)
      const size = Number(url.searchParams.get('page_size') ?? 50)
      const all = [...findings.values()]
      return json(route, { items: all.slice((pageNo - 1) * size, pageNo * size), total: all.length, page: pageNo, page_size: size })
    }
    const statusMatch = /^\/findings\/([^/]+)\/status$/.exec(path)
    if (statusMatch && method === 'PUT') {
      const body = mock.writes.at(-1)!.body as Schemas['FindingTransition']
      const current = findings.get(statusMatch[1])!
      const updated = { ...current, status: body.status, reviewer_id: 'user:u-operator' }
      findings.set(current.finding_id, updated)
      return json(route, { ...updated, events: [] })
    }

    // Kill switch
    if (path === '/admin/kill-switch' && method === 'GET') return json(route, { active: mock.state.kill, enabled: mock.state.kill, db: mock.state.kill, env: false, updated_at: null, updated_by: null })
    if (path === '/admin/kill-switch') {
      if (options.killSwitchForbidden) return json(route, { detail: 'Platform admin required' }, 403)
      mock.state.kill = (mock.writes.at(-1)!.body as { enabled: boolean }).enabled
      return json(route, { active: mock.state.kill, enabled: mock.state.kill, db: mock.state.kill, env: false, updated_at: null, updated_by: 'user:u-admin' })
    }
    return json(route, { detail: `unmocked ${method} ${path}` }, 404)
  })
  return mock
}
