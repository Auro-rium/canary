import type { CampaignPolicy } from './contracts'

export interface CampaignEstimate {
  conversations: number
  /** Upper bound on target requests: one per turn of every conversation, capped by the request budget. */
  requests: number
  /** True when the request budget will stop the campaign before every turn of every trial runs. */
  truncated: boolean
  /** Lower bound on duration: requests / rate limit. Null when the rate limit is not positive. */
  minSeconds: number | null
  /** LLM spend is capped, not predicted: the campaign stops at this amount. */
  costCapUsd: number
}

type Input = Pick<CampaignPolicy, 'techniques' | 'trials_per_technique' | 'max_turns' | 'max_total_requests' | 'rate_limit_rps' | 'max_llm_cost_usd'>

const nonNegative = (value: number) => (Number.isFinite(value) && value > 0 ? value : 0)

export function estimateCampaign(policy: Input): CampaignEstimate {
  const conversations = policy.techniques.length * Math.floor(nonNegative(policy.trials_per_technique))
  const wanted = conversations * Math.floor(nonNegative(policy.max_turns))
  const budget = Math.floor(nonNegative(policy.max_total_requests))
  const requests = Math.min(wanted, budget)
  const rate = nonNegative(policy.rate_limit_rps)
  return {
    conversations, requests, truncated: wanted > budget,
    minSeconds: rate > 0 ? Math.ceil(requests / rate) : null,
    costCapUsd: nonNegative(policy.max_llm_cost_usd),
  }
}

export function formatSeconds(seconds: number | null): string {
  if (seconds === null) return 'unknown'
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.floor(seconds / 60)
  return minutes < 60 ? `${minutes} min ${seconds % 60} s` : `${Math.floor(minutes / 60)} h ${minutes % 60} min`
}
