export type RunStatus = 'running' | 'completed' | 'failed'
export type FindingStatus = 'open' | 'wont_fix' | 'false_positive' | 'inconclusive'

export interface LlmStats {
  calls: number
  prompt_tokens: number
  completion_tokens: number
  total_tokens: number
  latency_ms: number
}

export interface RunSummary {
  run_id: string
  target_id: string
  status: RunStatus
  error: string | null
  start_time: string | null
  end_time: string | null
  total_attacks: number
  successful_attacks: number
  success_rate: number
  llm_stats: LlmStats
}

export interface AttackObservation {
  status?: string
  endpoint?: string
  http_status?: number
  latency_ms?: number
  request_hash?: string
  response_hash?: string
  response_bytes?: number
  error_type?: string
  error?: string
}

export interface AttackRecord {
  id: number
  attempt_number: number
  strategy_type: string
  target_id: string | null
  finding_id: string | null
  prompt: string
  response: string
  success: boolean
  severity: string
  score: number
  score_threshold: number
  indicators: Record<string, unknown>
  observation: AttackObservation | null
  error: string | null
  timestamp: string | null
}

export interface LlmCall {
  id: number
  agent: string
  model: string
  latency_ms: number
  prompt_tokens: number
  completion_tokens: number
  total_tokens: number
  input_hash: string
  output_hash: string
  timestamp: string | null
}

export interface RunDetail extends RunSummary {
  attacks: AttackRecord[]
  llm_calls: LlmCall[]
}

export interface DashboardOverview {
  backend: { status: string; active_runs: number; target_allowlist_configured: boolean }
  campaigns: { total: number; by_status: Record<string, number>; targets: number }
  open_findings: { total: number; by_severity: Record<string, number> }
  llm_stats: LlmStats
}

export interface PaginatedRuns {
  items: RunSummary[]
  page: number
  page_size: number
  total: number
}

export interface TargetSummary {
  target_id: string
  campaign_count: number
  latest_run: RunSummary | null
  open_findings: number
}

export interface TargetsResponse { items: TargetSummary[] }

export interface TargetCoverage {
  target_id: string
  tested_classes: string[]
  untested_classes: string[]
  open_findings_by_class: Record<string, number>
  total_findings: number
  open_findings: number
}

export interface TargetTrend {
  date: string
  strategy: string
  attempts: number
  successes: number
  success_rate: number
}

export interface Finding {
  finding_id: string
  target_id: string
  component: string
  strategy: string
  asi_class: string
  atlas_technique: string
  severity: string
  status: FindingStatus
  first_seen_run: string
  last_seen_run: string
  seen_in_runs: string[]
  created_at: string | null
  updated_at: string | null
  latest_verdict?: FindingVerdict
}

export interface FindingVerdict {
  verdict_id: string
  verdict: string
  confidence: string
  threshold_used: number
  verdict_path: string
  rationale: string | null
  timestamp: string | null
}

export interface FindingAttempt {
  id: number
  run_id: string
  attempt_number: number
  strategy_type: string
  success: boolean
  severity: string
  score: number
  timestamp: string | null
}

export interface CampaignRunPayload {
  campaign_id: string
  target_url: string
  techniques: string[]
  headers?: Record<string, string>
  request_template?: string
  response_path?: string
}

export type SseEvent =
  | { type: 'agent_state'; payload: { agent_id: string; status: string; active_edge?: string } }
  | { type: 'log'; payload: { level: string; message: string } }
  | { type: 'finding'; payload: Record<string, unknown> }
  | { type: 'campaign_complete'; payload: { campaign_id: string; run_id: string } }
  | { type: 'campaign_failed'; payload: { campaign_id: string; run_id: string; status: string; message: string } }
