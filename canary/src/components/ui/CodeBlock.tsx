import type { ReactNode } from 'react'
import { cx } from './tones'

export type Segment = { kind: 'text' | 'redaction'; value: string; label?: string }

const REDACTION = /\[REDACTED(?::([A-Za-z0-9_.-]+))?\]/g

/** Split text on server-side redaction markers (`[REDACTED:api_key]`). Pure; the text is never parsed as markup. */
export function splitRedactions(text: string): Segment[] {
  const out: Segment[] = []
  let last = 0
  for (const match of text.matchAll(REDACTION)) {
    const index = match.index ?? 0
    if (index > last) out.push({ kind: 'text', value: text.slice(last, index) })
    out.push({ kind: 'redaction', value: match[0], label: match[1] })
    last = index + match[0].length
  }
  if (last < text.length) out.push({ kind: 'text', value: text.slice(last) })
  return out
}

/** Monospace text with redaction markers styled. Everything is rendered as React text nodes (inert). */
export function CodeBlock({ text, className, as: Tag = 'pre' }: { text: string; className?: string; as?: 'pre' | 'div' }): ReactNode {
  return (
    <Tag className={cx('whitespace-pre-wrap break-words font-mono text-xs', className)}>
      {splitRedactions(text).map((segment, index) => segment.kind === 'text'
        ? <span key={index}>{segment.value}</span>
        : <span key={index} data-redaction={segment.label ?? ''} title={segment.label ? `Redacted: ${segment.label}` : 'Redacted'}
            className="rounded-sm border border-dashed border-warn/60 bg-warn-soft px-1 font-semibold text-warn">{segment.value}</span>)}
    </Tag>
  )
}
