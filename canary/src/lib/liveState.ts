import type {
  ConversationStatus, MonitorHitPayload, SseEvent, TechniqueResult, TurnPayload, Verdict,
} from './contracts'
import type { BudgetState, CampaignDetail, CampaignStatus, ConversationSummary } from './v2'

export interface LiveCell extends ConversationSummary {
  hits: MonitorHitPayload[]
  /** Redacted previews received live; the full transcript comes from the API. */
  previews: TurnPayload[]
}

export interface LiveCampaign {
  campaignId: string
  status: CampaignStatus
  totalConversations: number
  cells: Record<string, LiveCell>
  budget: BudgetState | null
  results: TechniqueResult[]
  confirmed: number
  message: string | null
  cancelledReason: string | null
  lastSeq: number
}

export const TERMINAL_STATUSES: readonly ConversationStatus[] = [
  'stopped_budget', 'stopped_monitor', 'stopped_target_refusal_streak', 'stopped_target_error_streak',
  'stopped_killed', 'completed', 'cancelled', 'error',
]

export function emptyCampaign(campaignId: string): LiveCampaign {
  return {
    campaignId, status: 'queued', totalConversations: 0, cells: {}, budget: null,
    results: [], confirmed: 0, message: null, cancelledReason: null, lastSeq: 0,
  }
}

export function fromDetail(detail: CampaignDetail): LiveCampaign {
  const cells: Record<string, LiveCell> = {}
  for (const c of detail.conversations) cells[c.conversation_id] = { ...c, hits: [], previews: [] }
  return {
    campaignId: detail.campaign_id,
    status: detail.status,
    totalConversations: detail.total_conversations,
    cells,
    budget: detail.budget,
    results: detail.technique_results,
    confirmed: detail.confirmed,
    message: null,
    cancelledReason: null,
    lastSeq: detail.last_seq,
  }
}

function cellFor(state: LiveCampaign, id: string, technique = '', trial = 0): LiveCell {
  return state.cells[id] ?? { conversation_id: id, technique, trial_index: trial, status: 'running', turns: 0, verdict: null, hits: [], previews: [] }
}

/** Fold one SSE event into the campaign. Exhaustive over every event type. */
export function reduceEvent(state: LiveCampaign, event: SseEvent): LiveCampaign {
  if (event.seq <= state.lastSeq) return state
  const next: LiveCampaign = { ...state, lastSeq: event.seq }
  switch (event.type) {
    case 'campaign_started':
      return { ...next, status: 'running', totalConversations: event.payload.total_conversations }
    case 'conversation_started': {
      const p = event.payload
      return { ...next, cells: { ...state.cells, [p.conversation_id]: { ...cellFor(state, p.conversation_id, p.technique, p.trial_index), technique: p.technique, trial_index: p.trial_index, status: 'running' } } }
    }
    case 'turn': {
      const p = event.payload
      const cell = cellFor(state, p.conversation_id)
      return { ...next, cells: { ...state.cells, [p.conversation_id]: { ...cell, turns: Math.max(cell.turns, p.index + 1), previews: [...cell.previews, p] } } }
    }
    case 'monitor_hit': {
      const p = event.payload
      const cell = cellFor(state, p.conversation_id)
      return { ...next, cells: { ...state.cells, [p.conversation_id]: { ...cell, hits: [...cell.hits, p] } } }
    }
    case 'conversation_finished': {
      const p = event.payload
      const cell = cellFor(state, p.conversation_id)
      return { ...next, cells: { ...state.cells, [p.conversation_id]: { ...cell, status: p.status, turns: p.turns } } }
    }
    case 'verdict': {
      const v = event.payload.verdict
      const cell = cellFor(state, v.conversation_id)
      const verdict: Verdict = v.verdict
      const confirmed = Object.values({ ...state.cells, [v.conversation_id]: { ...cell, verdict } }).filter(c => c.verdict === 'confirmed').length
      return { ...next, confirmed, cells: { ...state.cells, [v.conversation_id]: { ...cell, verdict } } }
    }
    case 'budget_update': {
      const { requests_used, max_total_requests, llm_cost_usd, max_llm_cost_usd } = event.payload
      return { ...next, budget: { requests_used, max_total_requests, llm_cost_usd, max_llm_cost_usd } }
    }
    case 'campaign_complete':
      return { ...next, status: 'complete', results: event.payload.technique_results, confirmed: event.payload.confirmed }
    case 'campaign_failed':
      return { ...next, status: 'failed', message: event.payload.message }
    case 'campaign_cancelled':
      return { ...next, status: 'cancelled', cancelledReason: event.payload.reason }
    default: {
      const unreachable: never = event
      void unreachable
      return next
    }
  }
}

export function isCampaignTerminal(status: CampaignStatus): boolean {
  return status === 'complete' || status === 'failed' || status === 'cancelled'
}

export function budgetFraction(used: number, max: number): number {
  return max > 0 ? Math.min(1, Math.max(0, used / max)) : 0
}
