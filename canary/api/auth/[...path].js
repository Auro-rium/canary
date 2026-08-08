import {
  clearOAuthStateCookie,
  clearSessionCookie,
  getOAuthState,
  getSession,
  newOAuthState,
  setOAuthStateCookie,
  setSessionCookie,
  verifySessionToken,
} from '../../src/server/auth.js'

const originFor = (req) => {
  const forwardedProto = req.headers?.['x-forwarded-proto'] || (process.env.NODE_ENV === 'production' ? 'https' : 'http')
  return process.env.APP_URL?.replace(/\/$/, '') || `${forwardedProto}://${req.headers.host}`
}

const redirectUriFor = (req) => process.env.GITHUB_OAUTH_REDIRECT_URI || `${originFor(req)}/api/auth/callback`

const routeName = (req) => {
  const path = Array.isArray(req.query?.path) ? req.query.path : [req.query?.path]
  const parts = path.filter(Boolean)
  if (parts[0] === 'auth') parts.shift()
  return parts.join('/')
}

const json = (res, status, body) => {
  res.status(status).setHeader('cache-control', 'no-store').json(body)
}

const configured = () => Boolean(
  process.env.GITHUB_OAUTH_CLIENT_ID &&
  process.env.GITHUB_OAUTH_CLIENT_SECRET &&
  process.env.SESSION_SECRET
)

const allowedLogin = (login) => {
  const configuredLogins = (process.env.GITHUB_ALLOWED_LOGINS || '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean)
  if (!configuredLogins.length) return false
  return configuredLogins.includes(String(login).toLowerCase())
}

const exchangeCode = async (req, code) => {
  const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.GITHUB_OAUTH_CLIENT_ID,
      client_secret: process.env.GITHUB_OAUTH_CLIENT_SECRET,
      code,
      redirect_uri: redirectUriFor(req),
    }),
  })
  if (!tokenResponse.ok) throw new Error('GitHub token exchange failed')
  const token = await tokenResponse.json()
  if (!token.access_token) throw new Error('GitHub did not return an access token')
  return token.access_token
}

const githubUser = async (accessToken) => {
  const response = await fetch('https://api.github.com/user', {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'agent-canary-dashboard',
    },
  })
  if (!response.ok) throw new Error('GitHub identity lookup failed')
  return response.json()
}

export default async function handler(req, res) {
  const route = routeName(req)
  if (!['github', 'callback', 'session', 'logout'].includes(route)) {
    json(res, 404, { detail: 'Unknown authentication route.' })
    return
  }

  // Local development can intentionally bypass OAuth. Never enable this in
  // the hosted Vercel project; production defaults to AUTH_REQUIRED=true.
  if (process.env.AUTH_REQUIRED === 'false' && route === 'session') {
    return json(res, 200, {
      authenticated: true,
      user: { id: 'local', login: 'local-development', name: 'Local development', avatar_url: null },
    })
  }
  if (process.env.AUTH_REQUIRED === 'false' && route === 'logout') {
    clearSessionCookie(res)
    return json(res, 200, { authenticated: false })
  }

  if (!configured()) {
    json(res, 503, { detail: 'GitHub authentication is not configured.' })
    return
  }

  if (route === 'github') {
    if (req.method !== 'GET') return json(res, 405, { detail: 'Method not allowed.' })
    const state = newOAuthState()
    setOAuthStateCookie(res, state)
    const params = new URLSearchParams({
      client_id: process.env.GITHUB_OAUTH_CLIENT_ID,
      redirect_uri: redirectUriFor(req),
      scope: 'read:user',
      state,
    })
    res.redirect(302, `https://github.com/login/oauth/authorize?${params}`)
    return
  }

  if (route === 'session') {
    if (req.method !== 'GET') return json(res, 405, { detail: 'Method not allowed.' })
    const session = getSession(req)
    if (!session) return json(res, 200, { authenticated: false, user: null })
    return json(res, 200, { authenticated: true, user: {
      id: session.sub,
      login: session.login,
      name: session.name,
      avatar_url: session.avatar_url,
    } })
  }

  if (route === 'logout') {
    if (!['GET', 'POST'].includes(req.method || '')) return json(res, 405, { detail: 'Method not allowed.' })
    clearSessionCookie(res)
    json(res, 200, { authenticated: false })
    return
  }

  if (req.method !== 'GET') return json(res, 405, { detail: 'Method not allowed.' })
  const { code, state, error } = req.query || {}
  const expectedState = getOAuthState(req)
  clearOAuthStateCookie(res)
  if (error) return json(res, 401, { detail: 'GitHub authorization was cancelled.' })
  if (!code || !state || !expectedState || state !== expectedState) {
    return json(res, 401, { detail: 'Invalid GitHub authorization state.' })
  }

  try {
    const user = await githubUser(await exchangeCode(req, code))
    if (!user.id || !user.login || !allowedLogin(user.login)) {
      return json(res, 403, { detail: 'This GitHub account is not allowed to access Canary.' })
    }
    setSessionCookie(res, user)
    res.redirect(302, process.env.APP_URL?.replace(/\/$/, '') || originFor(req))
  } catch {
    json(res, 502, { detail: 'Unable to complete GitHub authentication.' })
  }
}

// Kept as a named export for focused tests and to make the session boundary
// explicit to future handlers. GitHub tokens never enter this browser session.
export { verifySessionToken }
