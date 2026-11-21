// Page-level layout helpers shared by every page. Colors come from the theme tokens (index.css).
import type { ReactNode } from 'react'
import { ErrorState, cx } from './ui'

export { buttonClass, inputClass, primaryButtonClass } from './ui'
export { StatusBadge } from './ui'

/** Standard page width and gutters. `docked` leaves room for the right-hand Drawer from xl. */
export function Page({ children, className, wide = false }: { children: ReactNode; className?: string; wide?: boolean }) {
  return <div className={cx('mx-auto w-full px-gutter py-section', wide ? 'max-w-[90rem]' : 'max-w-6xl', className)}>{children}</div>
}

export function PageHeader({ title, eyebrow, children, description }: { title: string; eyebrow?: string; children?: ReactNode; description?: ReactNode }) {
  return (
    <header className="mb-section flex flex-wrap items-end justify-between gap-x-4 gap-y-3">
      <div className="min-w-0">
        {eyebrow && <p className="text-xs font-semibold uppercase tracking-wide text-muted">{eyebrow}</p>}
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-muted">{description}</p>}
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  )
}

export function Metric({ label, value, tone = 'default' }: { label: string; value: string | number; tone?: 'default' | 'danger' | 'warning' }) {
  return (
    <div className="min-w-[8.5rem] rounded-lg border border-line bg-surface px-4 py-2.5 shadow-e1">
      <div className="text-xs text-muted">{label}</div>
      <div className={cx('mt-0.5 text-lg font-semibold', tone === 'danger' && 'text-danger', tone === 'warning' && 'text-warn')}>{value}</div>
    </div>
  )
}

export function Notice({ children, tone = 'warn' }: { children: ReactNode; tone?: 'warn' | 'info' }) {
  return (
    <div className={cx('rounded-lg border px-4 py-3', tone === 'warn' ? 'border-warn/40 bg-warn-soft text-warn' : 'border-info/40 bg-info-soft text-info')}>
      <span aria-hidden="true" className="mr-1.5 font-bold">{tone === 'warn' ? '!' : 'i'}</span>{children}
    </div>
  )
}

export function ErrorNotice({ message }: { message: string }) { return <ErrorState message={message} /> }

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cx('rounded-lg border border-line bg-surface p-4 shadow-e1', className)}>{children}</section>
}

export function SectionTitle({ children, id }: { children: ReactNode; id?: string }) {
  return <h2 id={id} className="mb-3 text-base font-semibold">{children}</h2>
}

