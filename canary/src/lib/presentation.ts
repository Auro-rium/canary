import type { ConversationStatus, Verdict } from './contracts'

export function formatDate(value: string | null | undefined) {
  return value ? new Date(value).toLocaleString() : '—'
}

export function formatDuration(milliseconds: number) {
  return milliseconds >= 1000 ? `${(milliseconds / 1000).toFixed(1)}s` : `${milliseconds.toFixed(0)}ms`
}

export function strategyLabel(value: string) {
  return value.replace(/[_-]/g, ' ').replace(/\b\w/g, char => char.toUpperCase())
}

export function percent(value: number) {
  return `${(value * 100).toFixed(0)}%`
}

export type Tone = 'neutral' | 'danger' | 'warn' | 'ok' | 'info' | 'violet' | 'fuchsia'

/**
 * How each conversation status looks (tone + glyph + words, never color alone) and what it means.
 * `reason` is the "why did it stop" line shown in the transcript drawer; null for non-stops.
 */
export const CONVERSATION_STATUS_STYLE: Record<ConversationStatus, { label: string; tone: Tone; icon: string; reason: string | null }> = {
  running: { label: 'running', tone: 'info', icon: '↻', reason: null },
  completed: { label: 'completed', tone: 'ok', icon: '✓', reason: null },
  stopped_budget: { label: 'stopped: budget', tone: 'warn', icon: '■', reason: 'The request or cost budget ran out.' },
  stopped_monitor: { label: 'stopped: monitor', tone: 'danger', icon: '■', reason: 'A monitor rule fired and stopped the conversation (critical stop).' },
  stopped_target_refusal_streak: { label: 'stopped: refusals', tone: 'info', icon: '■', reason: 'The target refused several turns in a row, so the attempt was ended.' },
  stopped_target_error_streak: { label: 'stopped: target errors', tone: 'fuchsia', icon: '■', reason: 'The target returned errors on several consecutive turns.' },
  stopped_planner_guardrail: { label: 'stopped: planner guardrail', tone: 'violet', icon: '■', reason: 'The attacker planner hit one of its own guardrails and could not continue.' },
  stopped_killed: { label: 'stopped: kill switch', tone: 'danger', icon: '■', reason: 'The global kill switch halted this conversation.' },
  cancelled: { label: 'cancelled', tone: 'neutral', icon: '■', reason: 'An operator cancelled the campaign.' },
  error: { label: 'error', tone: 'danger', icon: '✕', reason: 'The conversation ended with an internal error.' },
}

/** Style for any status string the server may send; unknown values read as errors. */
export function statusStyle(status: string) {
  return (CONVERSATION_STATUS_STYLE as Record<string, (typeof CONVERSATION_STATUS_STYLE)[ConversationStatus]>)[status] ?? CONVERSATION_STATUS_STYLE.error
}

export const VERDICT_STYLE: Record<Verdict, { tone: Tone; icon: string }> = {
  confirmed: { tone: 'danger', icon: '✕' },
  unconfirmed: { tone: 'ok', icon: '✓' },
  inconclusive: { tone: 'violet', icon: '?' },
  failed: { tone: 'fuchsia', icon: '!' },
}

/** Score may be null on older rows; never call number methods on it unguarded. */
export function formatScore(score: number | null | undefined): string {
  return typeof score === 'number' && Number.isFinite(score) ? score.toFixed(2) : 'n/a'
}

// Removed with the Findings page redesign.
export const pageClass = ''
export const gutter = ''
export const SEVERITY_STYLE: Record<string, string> = {}
