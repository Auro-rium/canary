/**
 * Vercel server-side proxy for the public, read-only dashboard.
 *
 * CANARY_API_URL and CANARY_API_TOKEN are server-only environment variables.
 * Requests are authenticated server-side with the configured backend token;
 * the browser never receives that token.
 */
export default async function handler(req, res) {
  const method = req.method || 'GET'
  if (!['GET', 'HEAD', 'POST', 'PUT'].includes(method)) {
    res.status(405).json({ detail: 'Method is not supported by the dashboard proxy.' })
    return
  }

  const upstream = process.env.CANARY_API_URL
  const token = process.env.CANARY_API_TOKEN
  if (!upstream || !token) {
    res.status(503).json({ detail: 'Dashboard backend is not configured.' })
    return
  }

  // Vercel's Node runtime normally exposes catch-all segments as `query.path`,
  // but deployments rooted at a nested directory can omit that field. Keep
  // the proxy working in both shapes by deriving the path from the URL.
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
    const headers = { Authorization: `Bearer ${token}` }
    if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type']
    const body = ['GET', 'HEAD'].includes(method)
      ? undefined
      : typeof req.body === 'string'
        ? req.body
        : JSON.stringify(req.body ?? {})
    const response = await fetch(upstreamUrl, { method, headers, body })
    res.status(response.status)
    const contentType = response.headers.get('content-type')
    if (contentType) res.setHeader('content-type', contentType)
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
