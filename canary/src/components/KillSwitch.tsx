import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ApiError, getKillSwitch, setKillSwitch } from '../lib/api'
import { can, PERMISSION, useMe } from '../lib/useMe'
import type { KillSwitchState } from '../lib/v2'
import { buttonClass, dangerButtonClass, Dialog, ErrorState, inputClass, useToast } from './ui'

interface KillContext { state: KillSwitchState | null; unknown: boolean; set: (state: KillSwitchState) => void }
const Ctx = createContext<KillContext>({ state: null, unknown: true, set: () => undefined })
const useKill = () => useContext(Ctx)

/** Shared kill-switch status (readable by every role), refreshed every 30s. */
export function KillSwitchProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<KillSwitchState | null>(null)
  const [unknown, setUnknown] = useState(true)
  const refresh = useCallback(() => {
    getKillSwitch().then(next => { setState(next); setUnknown(false) }).catch(() => setUnknown(true))
  }, [])
  useEffect(() => {
    refresh()
    const timer = window.setInterval(refresh, 30_000)
    return () => window.clearInterval(timer)
  }, [refresh])
  const value = useMemo<KillContext>(() => ({ state, unknown, set: next => { setState(next); setUnknown(false) } }), [state, unknown])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

/** Global status pill: visible to everyone, a link to the Admin page for those who may toggle it. */
export function KillSwitchPill() {
  const { me } = useMe()
  const { state, unknown } = useKill()
  const engaged = state?.active === true
  const label = unknown && !state ? 'unknown' : engaged ? 'ENGAGED' : 'off'
  const tone = engaged ? 'border-danger bg-danger-soft text-danger font-semibold' : 'border-line-strong bg-raised text-muted'
  const content = <><span aria-hidden="true">{engaged ? '■' : '○'}</span><span className="sr-only sm:not-sr-only">Kill switch:</span><span>{label}</span></>
  const cls = `inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs ${tone}`
  return can(me, PERMISSION.killSwitchWrite)
    ? <Link to="/admin" data-testid="kill-pill" className={cls} title="Open the kill switch controls">{content}</Link>
    : <span data-testid="kill-pill" className={cls}>{content}</span>
}

/**
 * The kill-switch toggle. Rendered only for callers with `kill_switch:write`, but the backend further
 * limits it to platform admins, which /me does not expose; a 403 therefore hides the control.
 */
export function KillSwitchControl() {
  const { state, set } = useKill()
  const toast = useToast()
  const [open, setOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [forbidden, setForbidden] = useState(false)
  const active = state?.active ?? false

  const apply = async () => {
    setBusy(true)
    setError(null)
    try {
      const next = await setKillSwitch({ enabled: !active, reason: reason.trim() || null })
      set(next)
      setOpen(false)
      setReason('')
      toast({ title: next.active ? 'Kill switch engaged' : 'Kill switch released', tone: next.active ? 'danger' : 'ok' })
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) { setForbidden(true); setOpen(false) } else setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (forbidden) return <span data-testid="kill-forbidden" className="text-xs text-muted">Kill switch is limited to platform admins</span>
  return (
    <span className="inline-flex flex-wrap items-center gap-3">
      {active && <span data-testid="kill-engaged" className="text-sm font-semibold text-danger"><span aria-hidden="true">■ </span>Kill switch engaged: campaigns halting</span>}
      <button type="button" data-testid="kill-open" onClick={() => setOpen(true)} className={dangerButtonClass}>{active ? 'Release kill switch' : 'Kill switch'}</button>
      <Dialog open={open} onClose={() => setOpen(false)} tone="danger" title={active ? 'Release the kill switch?' : 'Halt all campaigns?'} testId="kill-dialog"
        footer={<>
          <button type="button" onClick={() => setOpen(false)} className={buttonClass}>Back</button>
          <button type="button" data-testid="kill-confirm" disabled={busy || reason.trim().length < 3} onClick={apply} className={dangerButtonClass}>{active ? 'Release' : 'Halt everything'}</button>
        </>}>
        <p>{active ? 'Releasing lets new campaigns start again.' : 'This halts ALL running campaigns for every organisation within one turn. Use it for an emergency only.'}</p>
        <label className="block text-xs font-semibold text-muted">Reason (required)
          <input aria-label="Kill switch reason" className={`${inputClass} mt-1 font-normal`} placeholder="Why now?" value={reason} onChange={event => setReason(event.target.value)} />
        </label>
        {error && <ErrorState message={error} />}
      </Dialog>
    </span>
  )
}
