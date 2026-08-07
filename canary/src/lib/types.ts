export type Phase = 'idle' | 'running' | 'complete'
export type AgentStatus = 'idle' | 'active' | 'processing' | 'done' | 'error'

export interface LogEntry {
  timestamp: string
  level: 'SYSTEM' | 'ATTACK' | 'EVAL' | 'FINDING' | 'ERROR'
  message: string
}

export interface FindingPayload {
  finding_id: string
  technique_id: string
  asi_code: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  verdict: 'VULNERABLE' | 'RESILIENT' | 'INCONCLUSIVE'
  verdict_path: 'consensus' | 'heuristic_fallback'
  score: number
  adversarial_input: string
  target_response_summary: string
  deterministic_hits: string[]
  threshold_used: number
  recommendation: string
}

export interface CompletePayload {
  campaign_id: string
  run_id: string
  total_findings: number
  critical_count: number
  high_count: number
  duration_seconds: number
  findings: FindingPayload[]
}

export interface SSEEvent {
  type: string
  payload: unknown
}

export interface CanaryProject {
  project_id: string
  name: string
  slug: string
  repository?: string | null
  environment: string
  endpoint: string
  request_template: string
  response_path: string | null
  strategies: string[]
  gate: { block_on: string[]; max_new_findings: number }
  created_at: string | null
  updated_at: string | null
}

export interface CanaryRelease {
  release_id: string
  project_id: string
  commit_sha: string
  ref?: string | null
  event_name?: string | null
  is_baseline?: boolean
  environment: string
  run_id: string | null
  status: 'running' | 'completed' | 'failed'
  decision: 'pass' | 'warn' | 'block' | null
  baseline_release_id: string | null
  finding_ids: string[]
  summary: {
    total_findings?: number
    coverage?: number
    security_score?: number
    severity_counts?: Record<string, number>
    error?: string
  }
  comparison: {
    new_finding_ids?: string[]
    known_finding_ids?: string[]
    resolved_finding_ids?: string[]
    baseline_established?: boolean
    baseline_missing?: boolean
  }
  created_at: string | null
  completed_at: string | null
}
