import {
  PRODUCTION_FORBIDDEN_TECHNIQUES, PRODUCTION_LIMITS, type CampaignPolicy, type Environment,
} from './contracts'

export const STAGING_DEFAULTS: CampaignPolicy = {
  techniques: [],
  trials_per_technique: 5,
  max_turns: 8,
  max_parallel_conversations: 4,
  rate_limit_rps: 1,
  max_total_requests: 500,
  max_llm_cost_usd: 10,
  stop_on_first_confirmed: false,
  allow_destructive_tools: false,
}

/** Fields the UI locks (disabled) for production targets. */
export const PRODUCTION_LOCKED_FIELDS = [
  'rate_limit_rps', 'max_parallel_conversations', 'max_total_requests', 'allow_destructive_tools',
] as const

export function isForbiddenInProduction(technique: string): boolean {
  return (PRODUCTION_FORBIDDEN_TECHNIQUES as readonly string[]).includes(technique)
}

/** Force the section-4 limits and drop forbidden techniques (the API rejects, the UI clamps first). */
export function applySafeDefaults(policy: CampaignPolicy, environment: Environment): CampaignPolicy {
  if (environment !== 'production') return policy
  return {
    ...policy,
    techniques: policy.techniques.filter(t => !isForbiddenInProduction(t)),
    rate_limit_rps: Math.min(policy.rate_limit_rps, PRODUCTION_LIMITS.rate_limit_rps),
    max_parallel_conversations: Math.min(policy.max_parallel_conversations, PRODUCTION_LIMITS.max_parallel_conversations),
    max_total_requests: Math.min(policy.max_total_requests, PRODUCTION_LIMITS.max_total_requests),
    allow_destructive_tools: false,
  }
}

export function defaultPolicy(environment: Environment): CampaignPolicy {
  return applySafeDefaults(STAGING_DEFAULTS, environment)
}

/** Client-side mirror of the server rules; returns human-readable problems (empty = ok). */
export function validatePolicy(policy: CampaignPolicy, environment: Environment): string[] {
  const problems: string[] = []
  if (policy.techniques.length === 0) problems.push('Select at least one technique.')
  if (policy.trials_per_technique < 1) problems.push('Trials per technique must be at least 1.')
  if (policy.max_turns < 1) problems.push('Max turns must be at least 1.')
  if (policy.max_llm_cost_usd <= 0) problems.push('LLM cost budget must be positive.')
  if (environment === 'production') {
    if (policy.rate_limit_rps > PRODUCTION_LIMITS.rate_limit_rps) problems.push('Production: rate limit must be at most 1 request/second.')
    if (policy.max_parallel_conversations > PRODUCTION_LIMITS.max_parallel_conversations) problems.push('Production: at most 2 parallel conversations.')
    if (policy.max_total_requests > PRODUCTION_LIMITS.max_total_requests) problems.push('Production: at most 300 total requests.')
    if (policy.allow_destructive_tools) problems.push('Production: destructive tools are not allowed.')
    if (policy.techniques.some(isForbiddenInProduction)) problems.push('Production: resource-exhaustion techniques are staging-only.')
  }
  return problems
}
