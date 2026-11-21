import { cloneElement, useId, type ReactElement, type ReactNode } from 'react'

export const inputClass = 'w-full rounded-md border border-line-strong bg-surface px-3 py-2 text-sm text-fg placeholder:text-muted disabled:cursor-not-allowed disabled:bg-raised disabled:opacity-70'
const base = 'inline-flex items-center justify-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50'
export const buttonClass = `${base} border border-line-strong bg-surface hover:bg-raised`
export const primaryButtonClass = `${base} bg-accent text-accent-fg hover:bg-accent-hover`
export const dangerButtonClass = `${base} border border-danger/60 bg-danger-soft text-danger hover:bg-danger/15`

/** Label + control + hint wired together with htmlFor / aria-describedby. `children` is a single form control. */
export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactElement<{ id?: string; 'aria-describedby'?: string }> }) {
  const id = useId()
  const hintId = `${id}-hint`
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs font-semibold text-muted">{label}</label>
      {cloneElement(children, { id, 'aria-describedby': hint ? hintId : undefined })}
      {hint && <p id={hintId} className="mt-1 text-xs text-muted">{hint}</p>}
    </div>
  )
}
