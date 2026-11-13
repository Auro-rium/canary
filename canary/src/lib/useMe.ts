import { createContext, useContext } from 'react'
import type { Me, Role } from './v2'

export interface MeState {
  me: Me | null
  loading: boolean
  error: string | null
}

export const MeContext = createContext<MeState>({ me: null, loading: true, error: null })

export const useMe = () => useContext(MeContext)

export function hasRole(role: Role | undefined, ...allowed: Role[]) {
  return role !== undefined && allowed.includes(role)
}
