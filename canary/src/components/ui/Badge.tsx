import type { ReactNode } from 'react'
import { cx, TONE_CLASSES, type Tone } from './tones'

/** Meaning never rides on color alone: every badge carries a glyph and a text label. */
export function Badge({ tone = 'neutral', icon, children, className, mono }: {
  tone?: Tone
  icon?: string
  children: ReactNode
  className?: string
  mono?: boolean
}) {
  return (
    <span className={cx('inline-flex items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-xs font-medium', mono && 'font-mono', TONE_CLASSES[tone], className)}>
      {icon && <span aria-hidden="true">{icon}</span>}
      {children}
    </span>
  )
}

const SEVERITY: Record<string, { tone: Tone; icon: string }> = {
  critical: { tone: 'danger', icon: '◆' },
  high: { tone: 'warn', icon: '▲' },
  medium: { tone: 'info', icon: '■' },
  low: { tone: 'violet', icon: '●' },
  info: { tone: 'neutral', icon: '○' },
}

export const severityTone = (severity: string) => SEVERITY[severity] ?? SEVERITY.info

export function SeverityBadge({ severity }: { severity: string }) {
  const { tone, icon } = severityTone(severity)
  return <Badge tone={tone} icon={icon}>{severity}</Badge>
}

const STATUS: Record<string, { tone: Tone; icon: string }> = {
  complete: { tone: 'ok', icon: '✓' },
  completed: { tone: 'ok', icon: '✓' },
  verified: { tone: 'ok', icon: '✓' },
  running: { tone: 'info', icon: '↻' },
  queued: { tone: 'neutral', icon: '…' },
  open: { tone: 'danger', icon: '●' },
  needs_review: { tone: 'warn', icon: '?' },
  inconclusive: { tone: 'violet', icon: '?' },
  wont_fix: { tone: 'neutral', icon: '–' },
  false_positive: { tone: 'neutral', icon: '✕' },
  failed: { tone: 'danger', icon: '✕' },
  cancelled: { tone: 'neutral', icon: '■' },
  unverified: { tone: 'warn', icon: '!' },
  production: { tone: 'danger', icon: '▲' },
  staging: { tone: 'neutral', icon: '○' },
}

export function StatusBadge({ status }: { status: string }) {
  const { tone, icon } = STATUS[status] ?? { tone: 'neutral' as Tone, icon: '•' }
  return <Badge tone={tone} icon={icon}>{status.replace(/_/g, ' ')}</Badge>
}

/** OWASP agentic-security class code, e.g. ASI01. */
export function AsiBadge({ code }: { code: string }) {
  return <Badge mono>{code}</Badge>
}
