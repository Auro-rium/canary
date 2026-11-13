import type { Environment, SessionMode, StreamingMode, TargetAuth } from './contracts'
import type { TargetCreateBody } from './v2'

export type AuthType = TargetAuth['type']

export const AUTH_TYPES: { value: AuthType; label: string }[] = [
  { value: 'none', label: 'None' },
  { value: 'bearer', label: 'Bearer token' },
  { value: 'header', label: 'Custom header' },
  { value: 'oauth_client_credentials', label: 'OAuth client credentials' },
  { value: 'cookie_login', label: 'Cookie login (username + password)' },
]

/** Flat form state; every secret lives only here and is never read back from the API. */
export interface TargetFormState {
  name: string
  endpoint: string
  environment: Environment
  authType: AuthType
  token: string
  headerName: string
  headerValue: string
  tokenUrl: string
  clientId: string
  clientSecret: string
  scope: string
  audience: string
  loginUrl: string
  username: string
  password: string
  usernameField: string
  passwordField: string
  sessionMode: SessionMode
  sessionIdPath: string
  requestTemplate: string
  responsePath: string
  toolTracePath: string
  streaming: StreamingMode
  timeoutS: number
}

export const EMPTY_TARGET_FORM: TargetFormState = {
  name: '', endpoint: '', environment: 'staging', authType: 'none',
  token: '', headerName: '', headerValue: '', tokenUrl: '', clientId: '', clientSecret: '', scope: '', audience: '',
  loginUrl: '', username: '', password: '', usernameField: 'username', passwordField: 'password',
  sessionMode: 'stateless_history', sessionIdPath: '', requestTemplate: '{"message": "{{MESSAGE}}"}',
  responsePath: '', toolTracePath: '', streaming: 'none', timeoutS: 60,
}

const PLACEHOLDER = /\{\{[^}]*\}\}/g
const ALLOWED = new Set(['{{MESSAGE}}', '{{SESSION_ID}}', '{{HISTORY}}'])

/** Mirrors the backend rules enough to give instant feedback; the server stays authoritative. */
export function validateTemplate(template: string): string | null {
  if (!template.trim()) return null
  try { JSON.parse(template) } catch { return 'Request template must be valid JSON.' }
  const tokens = template.match(PLACEHOLDER) ?? []
  for (const token of tokens) if (!ALLOWED.has(token)) return `Unknown placeholder ${token}. Allowed: {{MESSAGE}}, {{SESSION_ID}}, {{HISTORY}}.`
  const quoted = (name: string) => template.split(`"${name}"`).length - 1
  if (quoted('{{MESSAGE}}') !== 1) return 'Use "{{MESSAGE}}" exactly once, as a whole quoted JSON value.'
  if (tokens.length !== ['{{MESSAGE}}', '{{SESSION_ID}}', '{{HISTORY}}'].reduce((n, t) => n + quoted(t), 0)) {
    return 'Placeholders must be whole quoted values, never keys or part of a longer string.'
  }
  return null
}

export function buildAuth(form: TargetFormState): TargetAuth {
  switch (form.authType) {
    case 'none': return { type: 'none' }
    case 'bearer': return { type: 'bearer', token: form.token }
    case 'header': return { type: 'header', header_name: form.headerName, value: form.headerValue }
    case 'oauth_client_credentials':
      return { type: 'oauth_client_credentials', token_url: form.tokenUrl, client_id: form.clientId, client_secret: form.clientSecret, scope: form.scope || null, audience: form.audience || null }
    case 'cookie_login':
      return { type: 'cookie_login', login_url: form.loginUrl, username: form.username, password: form.password, username_field: form.usernameField, password_field: form.passwordField }
  }
}

export function validateTarget(form: TargetFormState): string[] {
  const problems: string[] = []
  if (!form.name.trim()) problems.push('Name is required.')
  if (!/^https?:\/\//i.test(form.endpoint.trim())) problems.push('Endpoint must be an http(s) URL.')
  const auth = buildAuth(form)
  const secret = auth.type === 'bearer' ? auth.token : auth.type === 'header' ? auth.value
    : auth.type === 'oauth_client_credentials' ? auth.client_secret : auth.type === 'cookie_login' ? auth.password : 'n/a'
  if (!secret.trim()) problems.push('The secret for the chosen auth type is required.')
  if (auth.type === 'header' && !auth.header_name.trim()) problems.push('Header name is required.')
  if (form.sessionMode === 'server_session' && !form.sessionIdPath.trim()) problems.push('Server session mode needs the session id path.')
  const templateProblem = validateTemplate(form.requestTemplate)
  if (templateProblem) problems.push(templateProblem)
  return problems
}

export function buildTargetBody(form: TargetFormState): TargetCreateBody {
  return {
    name: form.name.trim(),
    endpoint: form.endpoint.trim(),
    environment: form.environment,
    auth: buildAuth(form),
    session_mode: form.sessionMode,
    session_id_path: form.sessionIdPath.trim() || null,
    request_template: form.requestTemplate.trim() || null,
    response_path: form.responsePath.trim() || null,
    tool_trace_path: form.toolTracePath.trim() || null,
    streaming: form.streaming,
    timeout_s: form.timeoutS,
  }
}
