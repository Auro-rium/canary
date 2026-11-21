import type { ReactNode } from 'react'

export function ErrorState({ title = 'Something went wrong', message, onRetry, children }: { title?: string; message: string; onRetry?: () => void; children?: ReactNode }) {
  return (
    <div role="alert" className="rounded-lg border border-danger/40 bg-danger-soft px-4 py-3 text-danger">
      <p className="font-semibold"><span aria-hidden="true">✕ </span>{title}</p>
      <p className="mt-0.5 break-words">{message}</p>
      {children}
      {onRetry && <button type="button" onClick={onRetry} className="mt-2 rounded-md border border-danger/50 px-3 py-1 text-xs font-medium hover:bg-danger/10">Try again</button>}
    </div>
  )
}
