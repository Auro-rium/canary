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
