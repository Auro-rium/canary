import { authRequired, getSession, isSameOriginRequest } from '../src/server/auth.js'

/**
 * Vercel server-side proxy for the authenticated dashboard.
 *
 * CANARY_API_URL and CANARY_API_TOKEN are server-only environment variables.
 * GitHub OAuth protects the browser session; the scoped backend credential is
 * never bundled into Vite or exposed to the browser.
 */
export default async function handler(req, res) {
  const method = req.method || 'GET'
  const session = getSession(req)
  if (authRequired() && !session) {
    res.status(401).json({ detail: 'Sign in with GitHub to access the Canary dashboard.' })
    return
  }
  if (!isSameOriginRequest(req)) {
    res.status(403).json({ detail: 'Cross-origin dashboard requests are not allowed.' })
    return
  }
  if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    res.status(405).json({ detail: 'Method not allowed.' })
    return
  }

  const upstream = process.env.CANARY_API_URL
  const token = process.env.CANARY_API_TOKEN
  if (!upstream || !token) {
    res.status(503).json({ detail: 'Dashboard backend is not configured.' })
    return
  }

  const requestPath = String(req.url || '').split('?')[0]
  const marker = '/api/'
  let path
  if (requestPath.includes(marker)) {
    path = requestPath.slice(requestPath.indexOf(marker) + marker.length)
  } else {
    const segments = Array.isArray(req.query.path) ? req.query.path : [req.query.path]
    path = segments.filter(Boolean).join('/')
  }
  path = path.split('/').filter(Boolean).map(encodeURIComponent).join('/')
  if (!path || path.includes('..')) {
    res.status(400).json({ detail: 'Invalid API path.' })
    return
  }
  const queryIndex = req.url.indexOf('?')
  const query = queryIndex >= 0 ? req.url.slice(queryIndex) : ''
  const upstreamUrl = `${upstream.replace(/\/$/, '')}/api/${path}${query}`

  try {
    const headers = { Authorization: `Bearer ${token}` }
    if (req.headers?.['content-type']) headers['content-type'] = req.headers['content-type']
    if (session?.login) headers['x-canary-actor'] = session.login
    let body
    if (!['GET', 'HEAD'].includes(method)) {
      body = typeof req.body === 'string' ? req.body : req.body === undefined ? undefined : JSON.stringify(req.body)
    }
    const response = await fetch(upstreamUrl, {
      method,
      headers,
      body,
    })
    res.status(response.status)
    const contentType = response.headers.get('content-type')
    if (contentType) res.setHeader('content-type', contentType)
    res.setHeader('cache-control', 'no-store')
    res.send(Buffer.from(await response.arrayBuffer()))
  } catch {
    res.status(502).json({ detail: 'Canary backend is unavailable.' })
  }
}
