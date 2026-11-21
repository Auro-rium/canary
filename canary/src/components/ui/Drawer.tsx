import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

/**
 * Side panel. Below `xl` it covers the screen; from `xl` it docks to the right edge under the top bar
 * (the page reserves room for it, so the page behind stays usable) as a non-modal dialog. Below `xl` it is
 * modal: the app root is made inert, aria-modal is true and Tab is trapped inside. In both modes Escape or the
 * close button dismisses it, focus moves in on open and returns to the opener on close.
 */
const BELOW_XL = '(max-width: 1279.98px)'

function useModalViewport() {
  const [modal, setModal] = useState(() => window.matchMedia(BELOW_XL).matches)
  useEffect(() => {
    const query = window.matchMedia(BELOW_XL)
    const update = () => setModal(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])
  return modal
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

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
  const modal = useModalViewport()

  useEffect(() => {
    if (!open) return
    opener.current = document.activeElement
    const root = document.getElementById('root')
    if (modal && root) root.inert = true
    panel.current?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { onClose(); return }
      if (!modal || event.key !== 'Tab' || !panel.current) return
      const items = [...panel.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(el => !el.hasAttribute('inert') && el.offsetParent !== null)
      if (items.length === 0) { event.preventDefault(); panel.current.focus(); return }
      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement
      if (event.shiftKey && (active === first || active === panel.current || !panel.current.contains(active))) { event.preventDefault(); last.focus() }
      else if (!event.shiftKey && (active === last || !panel.current.contains(active))) { event.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      if (root) root.inert = false
      const previous = opener.current
      if (previous instanceof HTMLElement && document.contains(previous)) previous.focus()
    }
  }, [open, onClose, modal])

  if (!open) return null
  return createPortal(
    <aside ref={panel} tabIndex={-1} role="dialog" aria-modal={modal} aria-labelledby={titleId} data-testid={testId}
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
    </aside>,
    document.body,
  )
}
