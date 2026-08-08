/**
 * Vercel server-side proxy for the public, read-only dashboard.
 *
 * CANARY_API_URL and CANARY_API_TOKEN are server-only environment variables.
 * This intentionally permits GET/HEAD only: running attacks and registering
 * targets belongs to the GitHub Action, not an unauthenticated browser.
 */
export default async function handler(req, res) {
  if (!['GET', 'HEAD'].includes(req.method || '')) {
    res.status(405).json({ detail: 'Dashboard proxy is read-only. Run Canary from GitHub Actions.' })
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
  const rawPath = req.query.path ?? req.url.split('?')[0].replace(/^\/api\/?/, '')
  const segments = Array.isArray(rawPath) ? rawPath : [rawPath]
  const path = segments.filter(Boolean).map(encodeURIComponent).join('/')
  if (!path || path.includes('..')) {
    res.status(400).json({ detail: 'Invalid API path.' })
    return
  }
  const queryIndex = req.url.indexOf('?')
  const query = queryIndex >= 0 ? req.url.slice(queryIndex) : ''
  const upstreamUrl = `${upstream.replace(/\/$/, '')}/api/${path}${query}`

  try {
    const response = await fetch(upstreamUrl, {
      headers: { Authorization: `Bearer ${token}` },
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
