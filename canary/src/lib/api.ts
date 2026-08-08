import type { CanaryProject, CanaryRelease, SSEEvent } from './types'

// The browser always talks to a same-origin, read-only proxy. The proxy holds
// CANARY_API_TOKEN server-side; no bearer credential is bundled into Vite.
export const API_BASE = ''

export const authHeader = (): Record<string, string> => ({
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

// ─── Status ─────────────────────────────────────────────────────────────────
export const getStatus = () => apiFetch<unknown>('/api/status')

// ─── CUTC projects and release gates ───────────────────────────────────────
export const getProjects = () => apiFetch<CanaryProject[]>('/api/projects')
export const verifyTarget = (body: { endpoint: string; request_template: string; response_path?: string }) =>
  apiFetch<{ reachable: boolean; status_code: number; response_path_detected: boolean | null }>('/api/projects/verify-target', {
    method: 'POST',
    body: JSON.stringify(body),
  })
export const createProject = (body: {
  name: string
  endpoint: string
  environment: string
  request_template: string
  response_path?: string
  strategies: string[]
  gate: {
    block_on: string[]
    warn_on?: string[]
    max_new_blocking_findings?: number | null
    max_new_nonblocking_findings?: number | null
  }
}) => apiFetch<CanaryProject>('/api/projects', { method: 'POST', body: JSON.stringify(body) })

export const getProjectReleases = (projectId: string) =>
  apiFetch<CanaryRelease[]>(`/api/projects/${projectId}/releases`)

export const getProjectBaselines = (projectId: string) =>
  apiFetch<unknown[]>(`/api/projects/${projectId}/baselines`)

export const acceptProjectBaseline = (projectId: string, releaseId: string, reason = '') =>
  apiFetch<unknown>(`/api/projects/${projectId}/baselines/${releaseId}/accept?reason=${encodeURIComponent(reason)}`, {
    method: 'POST',
  })

export const getReleaseRegressions = (releaseId: string) =>
  apiFetch<unknown[]>(`/api/releases/${releaseId}/regressions`)

export const createProjectRelease = (projectId: string, body: { commit_sha: string; environment?: string }) =>
  apiFetch<CanaryRelease>(`/api/projects/${projectId}/releases`, { method: 'POST', body: JSON.stringify(body) })

// ─── Runs ───────────────────────────────────────────────────────────────────
export const createRun = (body: { target_id: string; strategy?: string; intensity?: string }) =>
  apiFetch<{ run_id: string; status: string; target_id: string }>('/api/runs', {
    method: 'POST',
    body: JSON.stringify(body),
  })

export const getRun = (runId: string) => apiFetch<unknown>(`/api/runs/${runId}`)
export const getRunAnalysisReport = (runId: string) => apiFetch<unknown>(`/api/runs/${runId}/analysis-report`)
export const getRunReportMarkdown = (runId: string) => apiFetch<{ markdown: string }>(`/api/runs/${runId}/report-markdown`)
export const getRunFindings = (runId: string) => apiFetch<unknown[]>(`/api/runs/${runId}/findings`)

// ─── Findings ───────────────────────────────────────────────────────────────
export const getOpenFindings = () => apiFetch<unknown[]>('/api/open-findings')
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
