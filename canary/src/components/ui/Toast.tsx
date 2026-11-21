import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { TONE_CLASSES, cx, type Tone } from './tones'

export interface ToastInput { title: string; description?: string; tone?: Extract<Tone, 'ok' | 'danger' | 'info' | 'warn'> }
interface ToastItem extends ToastInput { id: number }

const ToastContext = createContext<(toast: ToastInput) => void>(() => undefined)
export const useToast = () => useContext(ToastContext)

const ICON = { ok: '✓', danger: '✕', info: 'i', warn: '!' } as const

/** Polite live region; toasts dismiss themselves after 6s and can be closed by keyboard. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const next = useRef(1)
  const dismiss = useCallback((id: number) => setItems(list => list.filter(item => item.id !== id)), [])
  const push = useCallback((toast: ToastInput) => {
    const id = next.current++
    setItems(list => [...list.slice(-3), { ...toast, id }])
    window.setTimeout(() => dismiss(id), 6000)
  }, [dismiss])
  const value = useMemo(() => push, [push])
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div role="status" aria-live="polite" className="pointer-events-none fixed inset-x-3 bottom-3 z-50 flex flex-col items-end gap-2 sm:left-auto sm:w-96">
        {items.map(item => (
          <div key={item.id} data-testid="toast" className={cx('pointer-events-auto flex w-full items-start gap-2 rounded-lg border p-3 shadow-e2', TONE_CLASSES[item.tone ?? 'info'])}>
            <span aria-hidden="true" className="font-bold">{ICON[item.tone ?? 'info']}</span>
            <div className="min-w-0 flex-1">
              <p className="font-semibold">{item.title}</p>
              {item.description && <p className="break-words text-xs">{item.description}</p>}
            </div>
            <button type="button" onClick={() => dismiss(item.id)} aria-label="Dismiss notification" className="rounded-sm px-1 hover:bg-fg/10"><span aria-hidden="true">✕</span></button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
