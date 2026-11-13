// API client for /api/v2. Auth is the session cookie only (credentials:
// 'include'); no token is read from the environment or sent from here.
import type { SseEvent } from './contracts'
import { ApiError, detailMessage } from './errors'
import { followEvents } from './sse'
import type {
  CampaignCreateBody, CampaignDetail, CampaignSummary, ConversationDetail, FindingStatus, FindingV2,
  KillSwitchState, Me, Paged, TargetCreateBody, TargetCreated, TargetView, TestConnectionResult,
  VerifyMethod, VerifyResult,
} from './v2'

export { ApiError } from './errors'

export const API_BASE = (import.meta.env as Record<string, string | undefined>).VITE_API_URL ?? ''

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (init.body !== undefined) headers['Content-Type'] = 'application/json'
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

// Targets (exists today)
export const listTargets = () => apiFetch<{ items: TargetView[] }>('/api/v2/targets')
export const getTarget = (id: string) => apiFetch<TargetView>(`/api/v2/targets/${enc(id)}`)
export const createTarget = (body: TargetCreateBody) =>
  apiFetch<TargetCreated>('/api/v2/targets', { method: 'POST', body: json(body) })
export const verifyTarget = (id: string, method: VerifyMethod) =>
  apiFetch<VerifyResult>(`/api/v2/targets/${enc(id)}/verify`, { method: 'POST', body: json({ method }) })
/** Assumed route; a 404/405 means the backend has no test endpoint yet. */
export const testTargetConnection = (id: string) =>
  apiFetch<TestConnectionResult>(`/api/v2/targets/${enc(id)}/test`, { method: 'POST', body: json({}) })

// Campaigns
export const createCampaign = (body: CampaignCreateBody) =>
  apiFetch<{ campaign_id: string }>('/api/v2/campaigns', { method: 'POST', body: json(body) })
export const listCampaigns = (query: URLSearchParams) =>
  apiFetch<Paged<CampaignSummary>>(`/api/v2/campaigns?${query}`)
export const getCampaign = (id: string) => apiFetch<CampaignDetail>(`/api/v2/campaigns/${enc(id)}`)
export const cancelCampaign = (id: string) =>
  apiFetch<{ status: string }>(`/api/v2/campaigns/${enc(id)}/cancel`, { method: 'POST', body: json({}) })
export const getConversation = (id: string) =>
  apiFetch<ConversationDetail>(`/api/v2/conversations/${enc(id)}`)
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
export const updateFindingStatus = (id: string, body: { status: FindingStatus; rationale?: string }) =>
  apiFetch<FindingV2>(`/api/v2/findings/${enc(id)}/status`, { method: 'PUT', body: json(body) })

// Admin
export const getKillSwitch = () => apiFetch<KillSwitchState>('/api/v2/admin/kill-switch')
export const setKillSwitch = (active: boolean, reason: string) =>
  apiFetch<KillSwitchState>('/api/v2/admin/kill-switch', { method: 'POST', body: json({ active, reason }) })
