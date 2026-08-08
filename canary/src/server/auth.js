import {
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto'

const SESSION_COOKIE = 'canary_session'
const OAUTH_STATE_COOKIE = 'canary_oauth_state'
const SESSION_MAX_AGE = 60 * 60 * 24 * 7
const OAUTH_STATE_MAX_AGE = 10 * 60

const base64url = (value) => Buffer.from(value).toString('base64url')

const secret = () => {
  const value = String(process.env.SESSION_SECRET || '').trim()
  if (!value || value.length < 32) return null
  return value
}

const sign = (payload) => {
  const key = secret()
  if (!key) throw new Error('SESSION_SECRET must be configured with at least 32 characters')
  return createHmac('sha256', key).update(payload).digest('base64url')
}

const sessionIdentity = (user) => ({
  sub: String(user.id),
  login: String(user.login),
  name: user.name ? String(user.name) : null,
  avatar_url: user.avatar_url || null,
})

export function createSessionToken(user) {
  const payload = base64url(JSON.stringify({
    ...sessionIdentity(user),
    exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE,
  }))
  return `${payload}.${sign(payload)}`
}

export function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null
  const parts = token.split('.')
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null

  try {
    const expected = sign(parts[0])
    const actualBuffer = Buffer.from(parts[1])
    const expectedBuffer = Buffer.from(expected)
    if (actualBuffer.length !== expectedBuffer.length || !timingSafeEqual(actualBuffer, expectedBuffer)) return null

    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
    if (!payload || typeof payload !== 'object' || !payload.sub || !payload.login) return null
    if (!Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null
    return payload
  } catch {
    return null
  }
}

export function getCookie(req, name) {
  const cookieHeader = req?.headers?.cookie
  if (!cookieHeader) return null
  for (const part of String(cookieHeader).split(';')) {
    const separator = part.indexOf('=')
    if (separator < 0) continue
    const key = part.slice(0, separator).trim()
    if (key !== name) continue
    const value = part.slice(separator + 1).trim()
    try {
      return decodeURIComponent(value)
    } catch {
      return null
    }
  }
  return null
}

const cookieOptions = (maxAge) => [
  `${maxAge === 0 ? 'Max-Age=0' : `Max-Age=${maxAge}`}`,
  'Path=/',
  'HttpOnly',
  'SameSite=Lax',
  ...(process.env.NODE_ENV === 'production' ? ['Secure'] : []),
].join('; ')

const appendCookie = (res, cookie) => {
  const current = res.getHeader?.('set-cookie') || res.getHeader?.('Set-Cookie')
  const values = Array.isArray(current) ? current : current ? [current] : []
  res.setHeader('Set-Cookie', [...values, cookie])
}

const setCookie = (res, name, value, maxAge) => {
  appendCookie(res, `${name}=${encodeURIComponent(value)}; ${cookieOptions(maxAge)}`)
}

const clearCookie = (res, name) => setCookie(res, name, '', 0)

export function setSessionCookie(res, user) {
  setCookie(res, SESSION_COOKIE, createSessionToken(user), SESSION_MAX_AGE)
}

export function clearSessionCookie(res) {
  clearCookie(res, SESSION_COOKIE)
}

export function newOAuthState() {
  return randomBytes(32).toString('base64url')
}

export function setOAuthStateCookie(res, state) {
  setCookie(res, OAUTH_STATE_COOKIE, state, OAUTH_STATE_MAX_AGE)
}

export function getOAuthState(req) {
  return getCookie(req, OAUTH_STATE_COOKIE)
}

export function clearOAuthStateCookie(res) {
  clearCookie(res, OAUTH_STATE_COOKIE)
}

export function getSession(req) {
  return verifySessionToken(getCookie(req, SESSION_COOKIE))
}

export function authRequired() {
  // Hosted hackathon development can opt into the bypass explicitly. Keep the
  // second flag separate so a stale AUTH_REQUIRED value cannot disable OAuth
  // on a normal production deployment.
  const developmentBypass = process.env.NODE_ENV !== 'production' || process.env.CANARY_DEV_BYPASS === 'true'
  return !(process.env.AUTH_REQUIRED === 'false' && developmentBypass)
}

export function authBypassEnabled() {
  return !authRequired()
}

export function isSameOriginRequest(req) {
  const origin = req?.headers?.origin
  if (!origin) return true
  const host = req?.headers?.['x-forwarded-host'] || req?.headers?.host
  if (!host) return false
  const protocol = req?.headers?.['x-forwarded-proto'] || (process.env.NODE_ENV === 'production' ? 'https' : 'http')
  try {
    const parsed = new URL(origin)
    return parsed.protocol === `${protocol}:` && parsed.host === host
  } catch {
    return false
  }
}
