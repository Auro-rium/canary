import { TECHNIQUE_IDS } from './techniques'

export type Command =
  | { type: 'CONNECT'; url: string }
  | { type: 'RUN'; techniques: string[]; invalid: string[] }
  | { type: 'SHOW_FINDINGS' }
  | { type: 'SHOW_INCIDENTS' }
  | { type: 'SHOW_COVERAGE'; targetId: string }
  | { type: 'SHOW_TRENDS'; targetId: string }
  | { type: 'SHOW_RUN'; runId: string }
  | { type: 'RERUN_LAST' }
  | { type: 'EXPORT' }
  | { type: 'HELP' }
  | { type: 'UNKNOWN'; raw: string }

export const HELP_TEXT = [
  'Available commands:',
  '  connect <url>              — set the target endpoint',
  `  run <slug,slug>            — run techniques (${TECHNIQUE_IDS.join(', ')})`,
  '  run all                    — run every technique',
  '  show findings              — list findings from the backend',
  '  show incidents             — list recent incidents',
  '  show coverage <target_id>  — ASI class coverage for a target',
  '  show trends <target_id>    — success-rate trends for a target',
  '  show run <run_id>          — run detail',
  '  re-run last                — replay the last stored campaign config',
  '  export                     — download the last campaign report as JSON',
  '  help                       — show this message',
].join('\n')

export function parseCommand(input: string): Command {
  const trimmed = input.trim()
  const lower = trimmed.toLowerCase()

  if (lower.startsWith('connect ')) {
    return { type: 'CONNECT', url: trimmed.slice(8).trim() }
  }

  if (lower === 'run all') {
    return { type: 'RUN', techniques: [...TECHNIQUE_IDS], invalid: [] }
  }

  if (lower.startsWith('run ')) {
    const list = trimmed.slice(4).split(',').map((s) => s.trim()).filter(Boolean)
    const techniques = list.filter((id) => TECHNIQUE_IDS.includes(id))
    const invalid = list.filter((id) => !TECHNIQUE_IDS.includes(id))
    return { type: 'RUN', techniques, invalid }
  }

  if (lower === 'show findings') return { type: 'SHOW_FINDINGS' }
  if (lower === 'show incidents') return { type: 'SHOW_INCIDENTS' }

  if (lower.startsWith('show coverage ')) {
    return { type: 'SHOW_COVERAGE', targetId: trimmed.slice(14).trim() }
  }
  if (lower.startsWith('show trends ')) {
    return { type: 'SHOW_TRENDS', targetId: trimmed.slice(12).trim() }
  }
  if (lower.startsWith('show run ')) {
    return { type: 'SHOW_RUN', runId: trimmed.slice(9).trim() }
  }

  if (lower === 're-run last' || lower === 'rerun last') return { type: 'RERUN_LAST' }
  if (lower === 'export') return { type: 'EXPORT' }
  if (lower === 'help' || lower === '?') return { type: 'HELP' }

  return { type: 'UNKNOWN', raw: trimmed }
}
