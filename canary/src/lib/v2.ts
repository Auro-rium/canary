// Request/response shapes for the /api/v2 routes that are not part of the
// frozen contracts (those live in ./contracts.ts). Targets exist today; the
// rest follow the WP8 spec and are ASSUMED until WP7/WP8 land. Keep this file
// in sync with the backend and list every change in the WP9 status notes.
import type {
  AsiCode, CampaignPolicy, Conversation, ConversationStatus, ConversationVerdict, Severity,
  TargetConfig, TargetConfigInput, TechniqueResult, Verdict,
} from './contracts'

export type Role = 'viewer' | 'operator' | 'admin'

/** GET /api/v2/me (assumed). */
export interface Me {
  user_id: string
  email: string | null
  role: Role
  org_id?: string | null
}

export interface Paged<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

/** Public view of a target: secrets are always masked. */
export type TargetView = TargetConfig & { allowed_auth_hosts: string[] }

export type VerifyMethod = 'http_wellknown' | 'dns_txt' | 'response_header'

export interface VerificationInstructions {
  http_wellknown: { url: string; content: string }
  dns_txt: { name: string; type: 'TXT'; value: string }
  response_header: { header: string; value: string }
}

/** POST /api/v2/targets body: TargetConfigInput minus target_id/verified (server-assigned). */
export type TargetCreateBody = Omit<TargetConfigInput, 'target_id'> & { allowed_auth_hosts?: string[] }

export interface TargetCreated {
  target: TargetView
  verification_token: string
  verification: VerificationInstructions
}

export interface VerifyResult {
  target: TargetView
  verified: boolean
  method: VerifyMethod
  reason: string
}

/** POST /api/v2/targets/{id}/test (assumed): one benign hello, parsed reply. */
export interface TestConnectionResult {
  ok: boolean
  http_status: number | null
  latency_ms: number
  reply_text: string | null
  session_ref: string | null
  error: string | null
}

export type CampaignStatus = 'queued' | 'running' | 'complete' | 'failed' | 'cancelled'

export interface CampaignSummary {
  campaign_id: string
  target_id: string
  target_name: string | null
  environment: 'staging' | 'production'
  status: CampaignStatus
  created_at: string
  finished_at: string | null
  confirmed: number
  total_conversations: number
}

export interface ConversationSummary {
  conversation_id: string
  technique: string
  trial_index: number
  status: ConversationStatus
  turns: number
  verdict: Verdict | null
}

export interface BudgetState {
  requests_used: number
  max_total_requests: number
  llm_cost_usd: number
  max_llm_cost_usd: number
}

/** GET /api/v2/campaigns/{id} (assumed). */
export interface CampaignDetail extends CampaignSummary {
  policy: CampaignPolicy
  conversations: ConversationSummary[]
  technique_results: TechniqueResult[]
  budget: BudgetState | null
  /** Highest SSE seq already folded into this snapshot; resume the stream after it. */
  last_seq: number
}

/** POST /api/v2/campaigns body (assumed): the target is already registered and verified. */
export interface CampaignCreateBody {
  target_id: string
  policy: CampaignPolicy
}

/** GET /api/v2/conversations/{id} (assumed): transcript redacted by default. */
export interface ConversationDetail {
  conversation: Conversation
  verdict: ConversationVerdict | null
}

export type FindingStatus = 'open' | 'inconclusive' | 'wont_fix' | 'false_positive'

/** GET /api/v2/findings item (assumed). `score` may be null (old rows). */
export interface FindingV2 {
  finding_id: string
  campaign_id: string
  conversation_id: string
  technique: string
  asi_class: AsiCode
  severity: Severity
  status: FindingStatus
  title: string | null
  rationale: string
  first_failing_turn: number | null
  score: number | null
  reviewer_id: string | null
  created_at: string
}

export interface KillSwitchState {
  active: boolean
  reason?: string | null
  set_by?: string | null
}
