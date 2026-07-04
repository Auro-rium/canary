import type { SSEEvent } from './types'

// Backend connection — empty string = relative URL, handled by nginx proxy
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const _env = (import.meta as any).env as Record<string, string>
export const API_BASE = _env.VITE_API_URL || ''
export const API_TOKEN = _env.VITE_API_TOKEN || ''

export const authHeader = (): Record<string, string> => ({
  'Authorization': `Bearer ${API_TOKEN}`,
  'Content-Type': 'application/json',
})

export class ApiError extends Error {
  status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.status = status
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...authHeader(), ...(init?.headers ?? {}) },
  })
  if (!res.ok) {
    let detail = ''
    try { detail = (await res.json())?.detail ?? '' } catch { /* body wasn't JSON */ }
    throw new ApiError(detail || `Backend responded ${res.status}`, res.status)
  }
  return res.json() as Promise<T>
}

// ─── Runs ───────────────────────────────────────────────────────────────────
export const getRun = (runId: string) => apiFetch<unknown>(`/api/runs/${runId}`)

// ─── Findings ───────────────────────────────────────────────────────────────
export const getFindings = (query: string) => apiFetch<unknown[]>(`/api/findings?${query}`)
export const getFinding = (findingId: string) => apiFetch<unknown>(`/api/findings/${findingId}`)
export const getFindingAttempts = (findingId: string) => apiFetch<unknown[]>(`/api/findings/${findingId}/attempts`)
export const updateFindingStatus = (findingId: string, body: Record<string, string | boolean>) =>
  apiFetch<unknown>(`/api/findings/${findingId}/status`, { method: 'PUT', body: JSON.stringify(body) })

// ─── Targets ────────────────────────────────────────────────────────────────
export const getTargetCoverage = (targetId: string) =>
  apiFetch<unknown>(`/api/targets/${encodeURIComponent(targetId)}/coverage`)
export const getTargetTrends = (targetId: string, days = 30) =>
  apiFetch<unknown>(`/api/targets/${encodeURIComponent(targetId)}/trends?days=${days}`)

// ─── Incidents ──────────────────────────────────────────────────────────────
export const getIncidents = () => apiFetch<unknown[]>('/api/incidents')

// ─── Campaigns (SSE) ────────────────────────────────────────────────────────
export interface CampaignRunPayload {
  campaign_id: string
  target_url: string
  techniques: string[]
  headers?: Record<string, string>
  request_template?: string
  response_path?: string
}

export async function runCampaignSSE(
  payload: CampaignRunPayload,
  onEvent: (event: SSEEvent) => void,
  opts?: { signal?: AbortSignal },
): Promise<void> {
  const res = await fetch(`${API_BASE}/api/campaigns/run`, {
    method: 'POST',
    headers: authHeader(),
    body: JSON.stringify(payload),
    signal: opts?.signal,
  })

  if (!res.ok) {
    let detail = ''
    try { detail = (await res.json())?.detail ?? '' } catch { /* body wasn't JSON */ }
    throw new ApiError(detail || `Backend responded ${res.status}`, res.status)
  }
  if (!res.body) throw new Error('No SSE stream body')

  const reader = res.body.getReader()
  const decoder = new TextDecoder()

  let buffer = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? '' // keep incomplete last line
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue
      try {
        onEvent(JSON.parse(line.slice(6)))
      } catch { /* skip malformed */ }
    }
  }
}
