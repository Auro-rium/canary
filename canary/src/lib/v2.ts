// Request/response shapes for the /api/v2 routes. Wire types come from the
// backend's OpenAPI contract via ./api-schema (generated: `npm run gen:api`;
// src/lib/apiSchema.test.ts fails when it drifts from openapi/v2.json).
// Hand-written types here only narrow or rename; they must stay assignable to
// the generated ones (see the compile-time checks at the bottom).
import type { Schemas } from './api-schema'
import type {
  Conversation, ConversationVerdict, TargetConfig, TargetConfigInput, TechniqueResult,
} from './contracts'

export type Role = Schemas['Me']['role']

/** GET /api/v2/me. `permissions` is authoritative for UI gating. */
export type Me = Schemas['Me']

export interface Paged<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

/** Public view of a target: secrets are always masked. */
export type TargetView = Schemas['TargetView']

export type VerifyMethod = Schemas['VerifyRequest']['method']
export type VerificationInstructions = Schemas['VerificationInstructions']

/** POST /api/v2/targets body: TargetConfigInput minus target_id/verified (server-assigned). */
export type TargetCreateBody = Omit<TargetConfigInput, 'target_id' | 'verified' | 'auth'> & {
  auth: TargetConfig['auth']
  allowed_auth_hosts?: string[]
}

export type TargetCreated = Schemas['TargetCreated']
export type VerifyResult = Schemas['VerifyResult']

export type CampaignStatus = Schemas['CampaignSummary']['status']
export type CampaignSummary = Schemas['CampaignSummary']
export type ConversationSummary = Schemas['ConversationSummary']
export type BudgetState = Schemas['BudgetState']
export type CampaignDetail = Schemas['CampaignDetail']
export type CampaignCreateBody = Schemas['CampaignCreate']
export type CancelResult = Schemas['CancelResult']

/** GET /api/v2/conversations/{id}: transcript redacted unless `raw` was requested and permitted. */
export interface ConversationDetail {
  conversation: Conversation
  verdict: ConversationVerdict | null
  /** True only when the server returned unredacted evidence (audited). */
  raw: boolean
}

export type FindingStatus = Schemas['FindingTransition']['status']
export type FindingV2 = Schemas['FindingView']
export type FindingDetail = Schemas['FindingDetail']
export type FindingTransitionBody = Schemas['FindingTransition']

export type KillSwitchState = Schemas['KillSwitchState']
export type KillSwitchBody = Schemas['KillSwitchBody']

export type ProvidersView = Schemas['ProvidersView']

// Compile-time alignment: a drift here is a tsc error.
type Assert<T extends true> = T
type _CreateBody = Assert<TargetCreateBody extends Schemas['TargetCreate'] ? true : false>
type _Tech = Assert<TechniqueResult extends Schemas['TechniqueResult'] ? true : false>
// (ConversationDetail is wider than the schema on purpose: the status enum also has
// stopped_planner_guardrail; apiSchema.test.ts checks the schema's values are a subset.)
export type { _CreateBody, _Tech }
