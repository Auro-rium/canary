import { createContext, useContext } from 'react'
import type { Me } from './v2'

export interface MeState {
  me: Me | null
  loading: boolean
  error: string | null
  /** /api/v2/me answered 401: nobody is signed in. */
  unauthenticated: boolean
}

export const MeContext = createContext<MeState>({ me: null, loading: true, error: null, unauthenticated: false })

export const useMe = () => useContext(MeContext)

/** Permission names the backend grants (auth/principal.py); /me returns the caller's set. */
export const PERMISSION = {
  targetsWrite: 'targets:write',
  campaignsLaunch: 'campaigns:launch',
  campaignsCancel: 'campaigns:cancel',
  findingsTriage: 'findings:triage',
  evidenceReadRaw: 'evidence:read_raw',
  killSwitchWrite: 'kill_switch:write',
} as const

/** UI gating only; the backend enforces every permission again. */
export function can(me: Me | null | undefined, permission: string): boolean {
  return !!me && me.permissions.includes(permission)
}
