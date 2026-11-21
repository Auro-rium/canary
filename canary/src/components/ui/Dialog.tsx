import { useEffect, useId, useRef, type ReactNode } from 'react'
import { cx } from './tones'

/** Modal dialog on the native <dialog> element: focus is trapped, the page behind is inert, Escape closes, focus returns. */
export function Dialog({ open, onClose, title, children, footer, tone = 'default', testId }: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  footer?: ReactNode
  tone?: 'default' | 'danger'
  testId?: string
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const titleId = useId()
  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    if (open && !dialog.open) dialog.showModal()
    if (!open && dialog.open) dialog.close()
  }, [open])
  return (
    <dialog ref={ref} aria-labelledby={titleId} data-testid={testId} onClose={onClose}
      className={cx('m-auto w-[min(32rem,calc(100vw-2rem))] rounded-lg border bg-surface p-0 text-fg shadow-e3', tone === 'danger' ? 'border-danger/60' : 'border-line')}>
      {open && (
        <div className="space-y-4 p-5">
          <h2 id={titleId} className="text-lg font-semibold">{title}</h2>
          <div className="space-y-3">{children}</div>
          {footer && <div className="flex flex-wrap justify-end gap-2">{footer}</div>}
        </div>
      )}
    </dialog>
  )
}
