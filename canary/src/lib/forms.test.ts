import { describe, expect, it } from 'vitest'
import { formatScore } from './presentation'
import { buildTargetBody, EMPTY_TARGET_FORM, validateTarget, validateTemplate } from './targetForm'

describe('formatScore', () => {
  it('does not crash on null', () => {
    expect(formatScore(null)).toBe('n/a')
    expect(formatScore(undefined)).toBe('n/a')
    expect(formatScore(0.5)).toBe('0.50')
  })
})

describe('request template validation', () => {
  it('accepts a whole quoted placeholder', () => {
    expect(validateTemplate('{"message": "{{MESSAGE}}", "sid": "{{SESSION_ID}}"}')).toBeNull()
  })
  it('rejects unknown, embedded, missing and invalid templates', () => {
    expect(validateTemplate('{"m": "{{PROMPT}}"}')).toMatch(/Unknown placeholder/)
    expect(validateTemplate('{"m": "hi {{MESSAGE}}"}')).not.toBeNull()
    expect(validateTemplate('{"m": "x"}')).not.toBeNull()
    expect(validateTemplate('{not json')).toMatch(/valid JSON/)
  })
})

describe('target form', () => {
  const base = { ...EMPTY_TARGET_FORM, name: 'a', endpoint: 'https://x.example.com/chat' }
  it('requires a secret for secret auth types and builds the typed body', () => {
    expect(validateTarget({ ...base, authType: 'bearer' }).join()).toMatch(/secret/)
    const ok = { ...base, authType: 'bearer' as const, token: 's3cret' }
    expect(validateTarget(ok)).toEqual([])
    expect(buildTargetBody(ok).auth).toEqual({ type: 'bearer', token: 's3cret' })
  })
  it('server_session needs a session id path', () => {
    expect(validateTarget({ ...base, sessionMode: 'server_session' }).join()).toMatch(/session id path/)
  })
})
