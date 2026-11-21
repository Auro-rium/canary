import type { ConversationStatus, Severity, Verdict } from './contracts'

export const pageClass = 'min-h-screen bg-black text-white font-mono pt-24'
export const gutter = 'px-6 sm:px-10 md:px-16 lg:px-20'

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

/** Tailwind classes for a conversation cell, covering every ConversationStatus. */
export const CONVERSATION_STATUS_STYLE: Record<ConversationStatus, { label: string; classes: string }> = {
  running: { label: 'running', classes: 'border-yellow-500/50 bg-yellow-950/30 text-yellow-300 animate-pulse' },
  completed: { label: 'completed', classes: 'border-emerald-600/40 bg-emerald-950/20 text-emerald-300' },
  stopped_budget: { label: 'stopped: budget', classes: 'border-orange-500/40 bg-orange-950/20 text-orange-300' },
  stopped_monitor: { label: 'stopped: monitor', classes: 'border-red-500/50 bg-red-950/30 text-red-300' },
  stopped_target_refusal_streak: { label: 'stopped: refusals', classes: 'border-sky-500/40 bg-sky-950/20 text-sky-300' },
  stopped_target_error_streak: { label: 'stopped: target errors', classes: 'border-fuchsia-500/40 bg-fuchsia-950/20 text-fuchsia-300' },
  stopped_planner_guardrail: { label: 'stopped: planner guardrail', classes: 'border-violet-500/40 bg-violet-950/20 text-violet-300' },
  stopped_killed: { label: 'stopped: kill switch', classes: 'border-red-600 bg-red-900/50 text-red-200' },
  cancelled: { label: 'cancelled', classes: 'border-white/30 bg-white/5 text-white/60' },
  error: { label: 'error', classes: 'border-red-600/60 bg-red-950/40 text-red-300' },
}

export const VERDICT_STYLE: Record<Verdict, string> = {
  confirmed: 'text-red-400',
  unconfirmed: 'text-emerald-300',
  inconclusive: 'text-yellow-300',
  failed: 'text-fuchsia-300',
}

export const SEVERITY_STYLE: Record<Severity, string> = {
  critical: 'text-red-400 border-red-600/40',
  high: 'text-orange-400 border-orange-500/40',
  medium: 'text-yellow-300 border-yellow-500/40',
  low: 'text-sky-300 border-sky-500/40',
  info: 'text-white/50 border-white/20',
}

/** Score may be null on older rows; never call number methods on it unguarded. */
export function formatScore(score: number | null | undefined): string {
  return typeof score === 'number' && Number.isFinite(score) ? score.toFixed(2) : 'n/a'
}
