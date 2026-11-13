import { useEffect, useState, type ReactNode } from 'react'
import { getMe } from '../lib/api'
import { MeContext, type MeState } from '../lib/useMe'

export function MeProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<MeState>({ me: null, loading: true, error: null })
  useEffect(() => {
    getMe()
      .then(me => setState({ me, loading: false, error: null }))
      .catch(error => setState({ me: null, loading: false, error: error.message }))
  }, [])
  return <MeContext.Provider value={state}>{children}</MeContext.Provider>
}
