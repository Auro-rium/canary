/**
 * Vercel server-side proxy.
 *
 * CANARY_API_URL is the only server-side setting. The proxy is a pure
 * forwarder: it passes the signed-in user's session (Cookie / Authorization)
 * through to the backend and relays Set-Cookie back. It never injects a master
 * token, so an anonymous caller reaches the backend anonymously and the backend
 * (auth + roles, WP8) decides. Authorization is enforced there, not here.
 */
const FORWARD_REQUEST_HEADERS = [
  'cookie', 'authorization', 'content-type', 'accept', 'last-event-id', 'x-csrf-token', 'x-api-key',
]
const ALLOWED_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']

export default async function handler(req, res) {
  const method = req.method || 'GET'
  if (!ALLOWED_METHODS.includes(method)) {
    res.status(405).json({ detail: 'Method is not supported by the proxy.' })
    return
  }

  const upstream = process.env.CANARY_API_URL
  if (!upstream) {
    res.status(503).json({ detail: 'Backend is not configured.' })
    return
  }

  // Vercel normally exposes catch-all segments as `query.path`, but nested
  // roots can omit it; derive the path from the URL in that case.
  const queryPath = req.query.path
  const hasQueryPath = (Array.isArray(queryPath) && queryPath.length > 0)
    || (typeof queryPath === 'string' && queryPath.length > 0)
  const rawPath = hasQueryPath
    ? queryPath
    : req.url.split('?')[0].startsWith('/api/') ? req.url.split('?')[0].slice(5) : ''
  const segments = Array.isArray(rawPath) ? rawPath : String(rawPath).split('/')
  const path = segments
    .filter(Boolean)
    .map((segment) => {
      try { return encodeURIComponent(decodeURIComponent(segment)) } catch { return encodeURIComponent(segment) }
    })
    .join('/')
  if (!path || path.includes('..')) {
    res.status(400).json({ detail: 'Invalid API path.' })
    return
  }
  const queryIndex = req.url.indexOf('?')
  const query = queryIndex >= 0 ? req.url.slice(queryIndex) : ''
  const upstreamUrl = `${upstream.replace(/\/$/, '')}/api/${path}${query}`

  try {
    const headers = {}
    for (const name of FORWARD_REQUEST_HEADERS) {
      if (req.headers[name]) headers[name] = req.headers[name]
    }
    const body = ['GET', 'HEAD'].includes(method)
      ? undefined
      : typeof req.body === 'string'
        ? req.body
        : req.body === undefined ? undefined : JSON.stringify(req.body)
    const response = await fetch(upstreamUrl, { method, headers, body, redirect: 'manual' })
    res.status(response.status)
    const contentType = response.headers.get('content-type')
    if (contentType) res.setHeader('content-type', contentType)
    const setCookies = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : []
    if (setCookies.length) res.setHeader('set-cookie', setCookies)
    const location = response.headers.get('location')
    if (location) res.setHeader('location', location)
    res.setHeader('cache-control', 'no-store')
    if (!response.body) {
      res.end()
      return
    }
    const reader = response.body.getReader()
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      res.write(Buffer.from(value))
    }
    res.end()
  } catch {
    res.status(502).json({ detail: 'Canary backend is unavailable.' })
  }
}
