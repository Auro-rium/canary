export interface AuthUser {
  id: string
  login: string
  name: string
  avatar_url?: string | null
}

export interface AuthSession {
  authenticated: boolean
  user: AuthUser | null
}

export async function getSession(): Promise<AuthSession> {
  const response = await fetch('/api/auth/session', { credentials: 'same-origin' })
  if (!response.ok) throw new Error('Unable to check Canary session')
  return response.json() as Promise<AuthSession>
}

export function loginWithGitHub(): void {
  window.location.assign('/api/auth/github')
}

export async function logout(): Promise<void> {
  const response = await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
  })
  if (!response.ok) throw new Error('Unable to sign out of Canary')
}
