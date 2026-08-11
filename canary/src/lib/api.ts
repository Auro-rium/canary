import type {
  CampaignRunPayload, DashboardOverview, Finding, FindingAttempt, PaginatedRuns,
  RunDetail, TargetCoverage, TargetTrend, TargetsResponse, SseEvent,
} from './types'

const env = import.meta.env as Record<string, string | undefined>
export const API_BASE = env.VITE_API_URL ?? ''
const localApiToken = env.VITE_API_TOKEN

function requestHeaders(init?: HeadersInit): HeadersInit {
  return {
    'Content-Type': 'application/json',
    ...(localApiToken ? { Authorization: `Bearer ${localApiToken}` } : {}),
    ...(init ?? {}),
  }
}

export class ApiError extends Error {
  readonly status?: number
  constructor(message: string, status?: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: requestHeaders(init?.headers),
  })
  if (!response.ok) {
    let detail = ''
    try { detail = (await response.json() as { detail?: string }).detail ?? '' } catch { /* non-JSON upstream response */ }
    throw new ApiError(detail || `Backend responded ${response.status}`, response.status)
  }
  return response.json() as Promise<T>
}

export const getOverview = () => apiFetch<DashboardOverview>('/api/dashboard/overview')
export const getTargets = () => apiFetch<TargetsResponse>('/api/targets')
export const getRuns = (query: URLSearchParams) => apiFetch<PaginatedRuns>(`/api/runs?${query}`)
export const getRun = (runId: string) => apiFetch<RunDetail>(`/api/runs/${encodeURIComponent(runId)}`)
export const getRunReportMarkdown = (runId: string) => apiFetch<{ run_id: string; markdown: string }>(`/api/runs/${encodeURIComponent(runId)}/report-markdown`)
export const getRunFindings = (runId: string) => apiFetch<Finding[]>(`/api/runs/${encodeURIComponent(runId)}/findings`)
export const getTargetCoverage = (target: string) => apiFetch<TargetCoverage>(`/api/targets/${encodeURIComponent(target)}/coverage`)
export const getTargetTrends = (target: string) => apiFetch<TargetTrend[]>(`/api/targets/${encodeURIComponent(target)}/trends`)
export const getFindings = (query: URLSearchParams) => apiFetch<Finding[]>(`/api/findings?${query}`)
export const getFinding = (id: string) => apiFetch<Finding>(`/api/findings/${encodeURIComponent(id)}`)
export const getFindingAttempts = (id: string) => apiFetch<FindingAttempt[]>(`/api/findings/${encodeURIComponent(id)}/attempts`)
export const updateFindingStatus = (id: string, body: { status: string; reviewer_id?: string; rationale?: string }) =>
  apiFetch<{ status: string }>(`/api/findings/${encodeURIComponent(id)}/status`, { method: 'PUT', body: JSON.stringify(body) })

export async function runCampaignSSE(
  payload: CampaignRunPayload,
  onEvent: (event: SseEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`${API_BASE}/api/campaigns/run`, {
    method: 'POST',
    headers: requestHeaders(),
    body: JSON.stringify(payload),
    signal,
  })
  if (!response.ok) {
    let detail = ''
    try { detail = (await response.json() as { detail?: string }).detail ?? '' } catch { /* non-JSON upstream response */ }
    throw new ApiError(detail || `Backend responded ${response.status}`, response.status)
  }
  if (!response.body) throw new ApiError('No SSE stream body')

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      if (!line.startsWith('data: ')) continue
      try { onEvent(JSON.parse(line.slice(6)) as SseEvent) } catch { /* ignore malformed frame, preserve stream */ }
    }
  }
}
