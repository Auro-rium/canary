// API client for /api/v2. Auth is the session cookie only (credentials:
// 'include'); no token is read from the environment or sent from here.
import type { SseEvent } from './contracts'
import { ApiError, detailMessage } from './errors'
import { followEvents } from './sse'
import type {
  CampaignCreateBody, CampaignDetail, CampaignSummary, CancelResult, ConversationDetail, FindingDetail,
  FindingTransitionBody, FindingV2, KillSwitchBody, KillSwitchState, Me, Paged, ProvidersView,
  TargetCreateBody, TargetCreated, TargetView, VerifyMethod, VerifyResult,
} from './v2'

export { ApiError } from './errors'

export const API_BASE = (import.meta.env as Record<string, string | undefined>).VITE_API_URL ?? ''

/** WP8 double-submit CSRF: the readable `canary_csrf` cookie is echoed in `X-CSRF-Token`. */
export const CSRF_COOKIE = 'canary_csrf'
export const CSRF_HEADER = 'X-CSRF-Token'
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

// /api/v2/me also returns the token (session logins); used when the cookie is not readable.
let csrfFallback: string | null = null
export function setCsrfFallback(token: string | null | undefined) { csrfFallback = token ?? null }

export function readCsrfToken(): string | null {
  try {
    for (const part of document.cookie.split(';')) {
      const [name, ...rest] = part.trim().split('=')
      if (name === CSRF_COOKIE) return decodeURIComponent(rest.join('='))
    }
  } catch { /* no document (tests) */ }
  return csrfFallback
}

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (init.body !== undefined) headers['Content-Type'] = 'application/json'
  if (!SAFE_METHODS.has((init.method ?? 'GET').toUpperCase())) {
    const csrf = readCsrfToken()
    if (csrf) headers[CSRF_HEADER] = csrf
  }
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: 'include',
    headers: { ...headers, ...(init.headers as Record<string, string> | undefined) },
  })
  if (!response.ok) {
    let detail: unknown
    try { detail = (await response.json() as { detail?: unknown }).detail } catch { /* non-JSON body */ }
    throw new ApiError(detailMessage(detail, `Backend responded ${response.status}`), response.status)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

const enc = encodeURIComponent
const json = (body: unknown) => JSON.stringify(body)

export const getMe = () => apiFetch<Me>('/api/v2/me')

// Auth (OIDC): the browser is redirected to the provider and back; the session
// and CSRF cookies are set by the callback.
export const listProviders = () => apiFetch<ProvidersView>('/api/v2/auth/providers')
export const loginUrl = (provider: string, next = '/') =>
  `${API_BASE}/api/v2/auth/login/${enc(provider)}?next=${enc(next)}`
export const logout = () => apiFetch<unknown>('/api/v2/auth/logout', { method: 'POST', body: json({}) })

// Targets
export const listTargets = () => apiFetch<{ items: TargetView[] }>('/api/v2/targets')
export const getTarget = (id: string) => apiFetch<TargetView>(`/api/v2/targets/${enc(id)}`)
export const createTarget = (body: TargetCreateBody) =>
  apiFetch<TargetCreated>('/api/v2/targets', { method: 'POST', body: json(body) })
export const verifyTarget = (id: string, method: VerifyMethod) =>
  apiFetch<VerifyResult>(`/api/v2/targets/${enc(id)}/verify`, { method: 'POST', body: json({ method }) })

// Campaigns
export const createCampaign = (body: CampaignCreateBody) =>
  apiFetch<CampaignDetail>('/api/v2/campaigns', { method: 'POST', body: json(body) })
export const listCampaigns = (query: URLSearchParams) =>
  apiFetch<Paged<CampaignSummary>>(`/api/v2/campaigns?${query}`)
export const getCampaign = (id: string) => apiFetch<CampaignDetail>(`/api/v2/campaigns/${enc(id)}`)
export const cancelCampaign = (id: string) =>
  apiFetch<CancelResult>(`/api/v2/campaigns/${enc(id)}/cancel`, { method: 'POST', body: json({}) })
/** Redacted by default. `raw` needs `evidence:read_raw` (403 otherwise) and is written to the audit log. */
export const getConversation = (id: string, raw = false) =>
  apiFetch<ConversationDetail>(`/api/v2/conversations/${enc(id)}${raw ? '?raw=true' : ''}`)
export const reportUrl = (campaignId: string, format: 'json' | 'md' | 'pdf') =>
  `${API_BASE}/api/v2/reports/${enc(campaignId)}?format=${format}`

/** Follow a campaign's events with Last-Event-ID resume (see ./sse). */
export function streamCampaignEvents(
  campaignId: string,
  options: {
    onEvent: (event: SseEvent) => void
    lastSeq?: number
    signal?: AbortSignal
    onStatus?: (status: 'connected' | 'reconnecting') => void
  },
): Promise<number> {
  return followEvents({ url: `${API_BASE}/api/v2/campaigns/${enc(campaignId)}/events`, ...options })
}

// Findings
export const listFindings = (query: URLSearchParams) => apiFetch<Paged<FindingV2>>(`/api/v2/findings?${query}`)
export const updateFindingStatus = (id: string, body: FindingTransitionBody) =>
  apiFetch<FindingDetail>(`/api/v2/findings/${enc(id)}/status`, { method: 'PUT', body: json(body) })

// Admin (kill switch: read for every role, write for platform admins only; the backend answers 403 otherwise)
export const getKillSwitch = () => apiFetch<KillSwitchState>('/api/v2/admin/kill-switch')
export const setKillSwitch = (body: KillSwitchBody) =>
  apiFetch<KillSwitchState>('/api/v2/admin/kill-switch', { method: 'POST', body: json(body) })
