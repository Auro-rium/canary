import test from 'node:test'
import assert from 'node:assert/strict'
import { authRequired, createSessionToken, getCookie, verifySessionToken } from '../src/server/auth.js'
import authHandler from '../api/auth/[...path].js'

process.env.SESSION_SECRET = 'test-session-secret-that-is-at-least-32-chars'
process.env.GITHUB_OAUTH_CLIENT_ID = 'test-client'
process.env.GITHUB_OAUTH_CLIENT_SECRET = 'test-secret'

test('session tokens are signed and round-trip the allowed identity fields', () => {
  const token = createSessionToken({ id: 42, login: 'Auro-rium', name: 'Canary Maintainer', avatar_url: null })
  assert.equal(verifySessionToken(token).login, 'Auro-rium')
  assert.equal(verifySessionToken(`${token}tampered`), null)
})

test('cookie parsing handles encoded values and ignores unrelated cookies', () => {
  const req = { headers: { cookie: `other=value; canary_session=${encodeURIComponent('a.b')}` } }
  assert.equal(getCookie(req, 'canary_session'), 'a.b')
  assert.equal(getCookie(req, 'missing'), null)
})

test('session endpoint is anonymous until GitHub OAuth completes', async () => {
  const result = { statusCode: 0, headers: {}, body: null }
  const res = {
    status(code) { result.statusCode = code; return this },
    setHeader(name, value) { result.headers[name] = value; return this },
    json(body) { result.body = body; return this },
  }
  await authHandler({ method: 'GET', query: { path: ['session'] }, headers: {} }, res)
  assert.equal(result.statusCode, 200)
  assert.deepEqual(result.body, { authenticated: false, user: null })
})

test('development bypass is explicit and production cannot inherit it', () => {
  const previousRequired = process.env.AUTH_REQUIRED
  const previousNodeEnv = process.env.NODE_ENV
  process.env.AUTH_REQUIRED = 'false'
  process.env.NODE_ENV = 'development'
  assert.equal(authRequired(), false)
  process.env.NODE_ENV = 'production'
  assert.equal(authRequired(), true)
  if (previousRequired === undefined) delete process.env.AUTH_REQUIRED
  else process.env.AUTH_REQUIRED = previousRequired
  if (previousNodeEnv === undefined) delete process.env.NODE_ENV
  else process.env.NODE_ENV = previousNodeEnv
})
