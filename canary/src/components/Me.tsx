import { useEffect, useState, type ReactNode } from 'react'
import { ApiError, getMe, setCsrfFallback } from '../lib/api'
import { MeContext, type MeState } from '../lib/useMe'

export function MeProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<MeState>({ me: null, loading: true, error: null, unauthenticated: false })
  useEffect(() => {
    getMe()
      .then(me => { setCsrfFallback(me.csrf_token); setState({ me, loading: false, error: null, unauthenticated: false }) })
      .catch(error => setState({
        me: null, loading: false, error: error.message,
        unauthenticated: error instanceof ApiError && error.status === 401,
      }))
  }, [])
  return <MeContext.Provider value={state}>{children}</MeContext.Provider>
}
