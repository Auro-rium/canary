import { cx } from './tones'

export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden="true" className={cx('animate-skeleton rounded-md bg-raised', className ?? 'h-4 w-full')} />
}

/** Placeholder rows while a list loads; announces "Loading" once. */
export function SkeletonList({ rows = 4, label = 'Loading' }: { rows?: number; label?: string }) {
  return (
    <div role="status" aria-busy="true" className="space-y-2">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, index) => <Skeleton key={index} className="h-10 w-full" />)}
    </div>
  )
}
