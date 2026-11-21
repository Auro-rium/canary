import { useCallback, useEffect, useState } from 'react'

export interface Loaded<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
  setData: (updater: (previous: T | null) => T | null) => void
}

/** Run an async loader whenever `key` changes; ignores results from superseded runs. Not a cache. */
export function useLoad<T>(load: () => Promise<T>, key: string): Loaded<T> {
  const [data, setState] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let live = true
    setLoading(true)
    load()
      .then(result => { if (live) { setState(result); setError(null) } })
      .catch(e => { if (live) setError((e as Error).message) })
      .finally(() => { if (live) setLoading(false) })
    return () => { live = false }
    // `key` stands in for the loader's inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick])
  const reload = useCallback(() => setTick(value => value + 1), [])
  return { data, error, loading, reload, setData: updater => setState(updater) }
}
