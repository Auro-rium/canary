const API = 'http://localhost:8000';

async function request<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(opts?.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json();
}

export const api = {
  status: () => request<{ status: string }>('/api/status'),
  createRun: (body: { target_id: string; strategy?: string; intensity?: string }) =>
    request<{ run_id: string; status: string }>('/api/runs', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  getRun: (runId: string) => request<any>(`/api/runs/${runId}`),
  getAnalysis: (runId: string) => request<any>(`/api/runs/${runId}/analysis-report`),
  applyPolicy: (runId: string) =>
    request<{ status: string; message: string }>(`/api/runs/${runId}/apply`, { method: 'POST' }),
  getIncidents: () => request<any[]>('/api/incidents'),
};
