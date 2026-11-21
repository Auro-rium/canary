import { useEffect, useId, useRef, type ReactNode } from 'react'

/**
 * Side panel. Below `xl` it covers the screen; from `xl` it docks to the right edge under the top bar
 * (the page reserves room for it, so the page behind stays usable). It is a non-modal dialog: Escape
 * or the close button dismisses it, focus moves in on open and returns to the opener on close.
 */
export function Drawer({ open, onClose, title, subtitle, children, testId }: {
  open: boolean
  onClose: () => void
  title: string
  subtitle?: ReactNode
  children: ReactNode
  testId?: string
}) {
  const titleId = useId()
  const panel = useRef<HTMLElement>(null)
  const opener = useRef<Element | null>(null)

  useEffect(() => {
    if (!open) return
    opener.current = document.activeElement
    panel.current?.focus()
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      const previous = opener.current
      if (previous instanceof HTMLElement && document.contains(previous)) previous.focus()
    }
  }, [open, onClose])

  if (!open) return null
  return (
    <aside ref={panel} tabIndex={-1} role="dialog" aria-modal="false" aria-labelledby={titleId} data-testid={testId}
      className="fixed inset-0 z-40 flex flex-col bg-surface shadow-e3 outline-none xl:inset-auto xl:bottom-0 xl:right-0 xl:top-bar xl:w-drawer xl:border-l xl:border-line">
      <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
        <div className="min-w-0">
          <h2 id={titleId} className="truncate text-base font-semibold">{title}</h2>
          {subtitle && <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted">{subtitle}</div>}
        </div>
        <button type="button" onClick={onClose} aria-label="Close panel" className="shrink-0 rounded-md border border-line-strong px-2.5 py-1 text-sm font-medium hover:bg-raised">
          <span aria-hidden="true">✕</span> <span>Close</span>
        </button>
      </header>
      <div tabIndex={0} role="region" aria-label={`${title} content`} className="min-h-0 flex-1 overflow-y-auto">{children}</div>
    </aside>
  )
}
