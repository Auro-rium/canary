// v2 contracts for the multi-turn platform (WP0).
// Mirror of cyber-redteam-foundry/src/cyberredteam/contracts.py. The Python
// models are authoritative (bounds, validators); change both in one commit.
// Legacy single-turn types stay in ./types.ts.

// ── Shared primitives ────────────────────────────────────────────────────────

/** Canonical ASI class code, ASI01..ASI10. */
export type AsiCode =
  | 'ASI01' | 'ASI02' | 'ASI03' | 'ASI04' | 'ASI05'
  | 'ASI06' | 'ASI07' | 'ASI08' | 'ASI09' | 'ASI10'

export const ASI_CODE_PATTERN = /^ASI(0[1-9]|10)$/

export function isAsiCode(value: string): value is AsiCode {
  return ASI_CODE_PATTERN.test(value)
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type Environment = 'staging' | 'production'
export type SessionMode = 'stateless_history' | 'server_session' | 'cookie'
export type StreamingMode = 'none' | 'sse' | 'ndjson'

/**
 * Secret fields are write-only. Send the real value when creating or updating
 * a target; the API always returns the mask "**********". Sending the mask (or
 * an empty string) back as a secret is rejected.
 */
export type WriteOnlySecret = string

export const SECRET_MASK = '**********'

// ── Target auth (discriminated on `type`) ────────────────────────────────────

export interface NoAuth {
  type: 'none'
}

export interface BearerAuth {
  type: 'bearer'
  token: WriteOnlySecret
}

export interface HeaderAuth {
  type: 'header'
  header_name: string
  value: WriteOnlySecret
}

export interface OAuthClientCredentialsAuth {
  type: 'oauth_client_credentials'
  token_url: string
  client_id: string
  client_secret: WriteOnlySecret
  scope?: string | null
  audience?: string | null
}

export interface CookieLoginAuth {
  type: 'cookie_login'
  login_url: string
  username: string
  password: WriteOnlySecret
  username_field?: string
  password_field?: string
}

export type TargetAuth =
  | NoAuth
  | BearerAuth
  | HeaderAuth
  | OAuthClientCredentialsAuth
  | CookieLoginAuth

// ── Target ───────────────────────────────────────────────────────────────────

/** Placeholders allowed in request_template; each must be a quoted JSON string. */
export const TEMPLATE_PLACEHOLDERS = ['{{MESSAGE}}', '{{SESSION_ID}}', '{{HISTORY}}'] as const

export interface TargetConfig {
  target_id: string // uuid
  name: string
  endpoint: string
  method: 'POST'
  auth: TargetAuth
  request_template: string | null
  response_path: string | null
  session_mode: SessionMode
  session_id_path: string | null
  tool_trace_path: string | null
  streaming: StreamingMode
  timeout_s: number
  verified: boolean
  environment: Environment
}

/**
 * Body for creating a target: fields with a server default are optional.
 * `verified` is omitted on purpose; only the ownership check (WP1) sets it.
 */
export type TargetConfigInput = Pick<
  TargetConfig,
  'target_id' | 'name' | 'endpoint' | 'session_mode' | 'environment'
> &
  Partial<
    Pick<
      TargetConfig,
      | 'method'
      | 'auth'
      | 'request_template'
      | 'response_path'
      | 'session_id_path'
      | 'tool_trace_path'
      | 'streaming'
      | 'timeout_s'
    >
  >

// ── Campaign policy ──────────────────────────────────────────────────────────

export interface CampaignPolicy {
  techniques: string[]
  trials_per_technique: number
  max_turns: number
  max_parallel_conversations: number
  rate_limit_rps: number
  max_total_requests: number
  max_llm_cost_usd: number
  stop_on_first_confirmed: boolean
  allow_destructive_tools: boolean
}

/** Body for a policy: only `techniques` is required; the rest have server defaults. */
export type CampaignPolicyInput = Pick<CampaignPolicy, 'techniques'> &
  Partial<Omit<CampaignPolicy, 'techniques'>>

/**
 * A campaign launch. Campaign creation always validates through this shape, so
 * the production rules below are applied against the target's environment.
 */
export interface CampaignRequest {
  target: TargetConfig
  policy: CampaignPolicy
}

export interface CampaignRequestInput {
  target: TargetConfigInput
  policy: CampaignPolicyInput
}

/** Section-4 limits; production policies above these are rejected by the API. */
export const PRODUCTION_LIMITS = {
  rate_limit_rps: 1,
  max_parallel_conversations: 2,
  max_total_requests: 300,
} as const

export const PRODUCTION_FORBIDDEN_TECHNIQUES = ['workflow_manipulation', 'denial-of-service'] as const

// ── Conversation records ─────────────────────────────────────────────────────

export interface ToolCallObservation {
  name: string
  arguments: Record<string, unknown>
  call_id: string | null
  source: 'structured' | 'heuristic'
}

export interface Turn {
  conversation_id: string
  index: number
  role_sent: 'user'
  message: string
  response_text: string
  tool_calls: ToolCallObservation[]
  http_status: number | null
  latency_ms: number
  monitor_hits: string[]
  error: string | null
}

export type ConversationStatus =
  | 'running'
  | 'stopped_budget'
  | 'stopped_monitor'
  | 'stopped_target_refusal_streak'
  | 'stopped_target_error_streak' // WP3: 3+ consecutive target errors
  | 'stopped_killed' // WP7: global kill switch
  | 'stopped_planner_guardrail' // the attacker planner hit a guardrail and could not continue
  | 'completed'
  | 'cancelled'
  | 'error'

export interface Conversation {
  conversation_id: string
  campaign_id: string
  technique: string
  trial_index: number
  status: ConversationStatus
  turns: Turn[]
  target_session_ref: string | null
}

// ── Evaluation ───────────────────────────────────────────────────────────────

export type Verdict = 'confirmed' | 'unconfirmed' | 'inconclusive' | 'failed'

export interface JudgeVote {
  vote_index: number
  judgement: 'unsafe' | 'safe' | 'inconclusive'
  first_failing_turn: number | null
  asi_class: AsiCode | null
  severity: Severity
  confidence: number
  rationale: string
  model_name: string | null
  /** Informational: Backboard has no temperature parameter. Defaults to 0. */
  temperature: number
}

export interface ConversationVerdict {
  conversation_id: string
  verdict: Verdict
  first_failing_turn: number | null
  deterministic_hits: string[]
  judge_votes: JudgeVote[]
  judge_agreement: number
  severity: Severity
  asi_class: AsiCode
  rationale: string
}

export interface TechniqueResult {
  technique: string
  trials: number
  confirmed: number
  success_rate: number
  ci95_low: number
  ci95_high: number
}

// ── SSE v2 events ────────────────────────────────────────────────────────────

export const SSE_EVENT_TYPES = [
  'campaign_started',
  'conversation_started',
  'turn',
  'monitor_hit',
  'conversation_finished',
  'verdict',
  'budget_update',
  'campaign_complete',
  'campaign_failed',
  'campaign_cancelled',
] as const

export type SseEventType = (typeof SSE_EVENT_TYPES)[number]

/** Turn previews are truncated (not rejected) to this length. */
export const PREVIEW_MAX_CHARS = 280
/** turn.error, the verdict event's rationale and campaign_failed.message are truncated to this length. */
export const TEXT_MAX_CHARS = 500

/** Same rule as the backend's truncate_preview(): cut to `limit` chars, ending in "…". */
export function truncatePreview(text: string, limit: number = PREVIEW_MAX_CHARS): string {
  return text.length <= limit ? text : text.slice(0, limit - 1) + '…'
}

export interface CampaignStartedPayload {
  campaign_id: string
  target_id: string
  environment: Environment
  techniques: string[]
  trials_per_technique: number
  total_conversations: number
}

export interface ConversationStartedPayload {
  campaign_id: string
  conversation_id: string
  technique: string
  trial_index: number
}

/** Redacted preview of a turn; full text comes from the conversation API. */
export interface TurnPayload {
  campaign_id: string
  conversation_id: string
  index: number
  message_preview: string
  response_preview: string
  tool_call_names: string[]
  http_status: number | null
  latency_ms: number
  monitor_hits: string[]
  error: string | null
}

export interface MonitorHitPayload {
  campaign_id: string
  conversation_id: string
  turn_index: number
  hit: string
  severity: Severity
  stops_conversation: boolean
}

export interface ConversationFinishedPayload {
  campaign_id: string
  conversation_id: string
  status: ConversationStatus
  turns: number
}

export interface VerdictPayload {
  campaign_id: string
  verdict: ConversationVerdict
}

export interface BudgetUpdatePayload {
  campaign_id: string
  requests_used: number
  max_total_requests: number
  llm_cost_usd: number
  max_llm_cost_usd: number
}

export interface CampaignCompletePayload {
  campaign_id: string
  conversations: number
  confirmed: number
  technique_results: TechniqueResult[]
  duration_seconds: number
}

export interface CampaignFailedPayload {
  campaign_id: string
  message: string
}

export interface CampaignCancelledPayload {
  campaign_id: string
  reason: 'user' | 'kill_switch' | 'budget'
  cancelled_by: string | null
}

export interface SsePayloadMap {
  campaign_started: CampaignStartedPayload
  conversation_started: ConversationStartedPayload
  turn: TurnPayload
  monitor_hit: MonitorHitPayload
  conversation_finished: ConversationFinishedPayload
  verdict: VerdictPayload
  budget_update: BudgetUpdatePayload
  campaign_complete: CampaignCompletePayload
  campaign_failed: CampaignFailedPayload
  campaign_cancelled: CampaignCancelledPayload
}

interface SseEnvelope<T extends SseEventType> {
  type: T
  payload: SsePayloadMap[T]
  timestamp: string // ISO 8601, UTC
  seq: number // also sent as the SSE `id:` line, for Last-Event-ID resume
}

/** Discriminated union: narrowing on `type` narrows `payload`. */
export type SseEvent = { [T in SseEventType]: SseEnvelope<T> }[SseEventType]

export function isSseEventType(value: string): value is SseEventType {
  return (SSE_EVENT_TYPES as readonly string[]).includes(value)
}
