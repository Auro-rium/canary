export type Tone = 'neutral' | 'danger' | 'warn' | 'ok' | 'info' | 'violet' | 'fuchsia'

/** Text + soft background + border for a tone. Pairs are chosen so every tone passes AA in both themes. */
export const TONE_CLASSES: Record<Tone, string> = {
  neutral: 'text-muted bg-raised border-line-strong/50',
  danger: 'text-danger bg-danger-soft border-danger/40',
  warn: 'text-warn bg-warn-soft border-warn/40',
  ok: 'text-ok bg-ok-soft border-ok/40',
  info: 'text-info bg-info-soft border-info/40',
  violet: 'text-violet bg-violet-soft border-violet/40',
  fuchsia: 'text-fuchsia bg-fuchsia-soft border-fuchsia/40',
}

export const cx = (...parts: Array<string | false | null | undefined>) => parts.filter(Boolean).join(' ')
