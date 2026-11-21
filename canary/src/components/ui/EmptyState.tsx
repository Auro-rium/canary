import type { ReactNode } from 'react'

export function EmptyState({ title, description, action, icon = '∅' }: { title: string; description?: ReactNode; action?: ReactNode; icon?: string }) {
  return (
    <div className="rounded-lg border border-dashed border-line-strong bg-surface px-6 py-10 text-center">
      <div aria-hidden="true" className="mx-auto mb-2 text-xl text-muted">{icon}</div>
      <p className="text-base font-semibold">{title}</p>
      {description && <p className="mx-auto mt-1 max-w-md text-muted">{description}</p>}
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  )
}
