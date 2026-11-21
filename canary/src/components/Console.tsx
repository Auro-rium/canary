import type { ReactNode } from 'react'
import { gutter } from '../lib/presentation'

export function PageHeader({ eyebrow, title, children }: { eyebrow: string; title: string; children?: ReactNode }) {
  return (
    <header className={`${gutter} py-10 border-b border-white/10`}>
      <p className="text-white/60 text-[10px] tracking-[0.28em] uppercase">// {eyebrow}</p>
      <div className="mt-4 flex flex-wrap gap-4 items-end justify-between">
        <h1 className="text-3xl sm:text-4xl font-bold uppercase tracking-[-0.04em]">{title}</h1>
        <div className="flex flex-wrap gap-3 items-center">{children}</div>
      </div>
    </header>
  )
}

export function Metric({ label, value, tone = 'default' }: { label: string; value: string | number; tone?: 'default' | 'danger' | 'warning' }) {
  const color = tone === 'danger' ? 'text-red-400' : tone === 'warning' ? 'text-orange-400' : 'text-white'
  return (
    <div className="border border-white/10 bg-white/[0.02] px-4 py-3 min-w-[140px]">
      <div className="text-white/60 text-[9px] uppercase tracking-[0.15em]">{label}</div>
      <div className={`mt-1 text-lg ${color}`}>{value}</div>
    </div>
  )
}

export function Badge({ children, className = 'text-white/60 border-white/20' }: { children: ReactNode; className?: string }) {
  return <span className={`inline-flex border px-2 py-1 text-[9px] uppercase tracking-[0.13em] ${className}`}>{children}</span>
}

const STATUS_TONE: Record<string, string> = {
  complete: 'text-emerald-300 border-emerald-600/30 bg-emerald-950/20',
  completed: 'text-emerald-300 border-emerald-600/30 bg-emerald-950/20',
  verified: 'text-emerald-300 border-emerald-600/30 bg-emerald-950/20',
  running: 'text-yellow-300 border-yellow-500/30 bg-yellow-950/20',
  queued: 'text-white/60 border-white/20',
  open: 'text-red-400 border-red-600/30 bg-red-950/20',
  failed: 'text-red-300 border-red-600/40 bg-red-950/40',
  cancelled: 'text-white/50 border-white/20',
  unverified: 'text-orange-300 border-orange-500/30 bg-orange-950/20',
  production: 'text-red-300 border-red-600/40 bg-red-950/30',
}

export function StatusBadge({ status }: { status: string }) {
  return <Badge className={STATUS_TONE[status] ?? 'text-white/60 border-white/20'}>{status.replace(/_/g, ' ')}</Badge>
}

export function ErrorNotice({ message }: { message: string }) {
  return <div role="alert" className="border border-red-600/30 bg-red-950/20 px-4 py-3 text-red-300 text-xs">{message}</div>
}

export function Notice({ children }: { children: ReactNode }) {
  return <div className="border border-yellow-500/30 bg-yellow-950/20 px-4 py-3 text-yellow-200 text-xs">{children}</div>
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="border border-dashed border-white/15 p-10 text-center text-white/60 text-xs uppercase tracking-[0.15em]">{children}</div>
}

export const inputClass = 'w-full bg-black border border-white/20 px-3 py-2 text-xs text-white placeholder-white/60 focus:border-white/60 outline-none disabled:opacity-40'
export const buttonClass = 'px-4 py-2 border border-white/25 text-xs uppercase tracking-wider hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed'
export const primaryButtonClass = 'px-4 py-2 bg-red-600 text-xs uppercase tracking-wider hover:bg-red-500 disabled:opacity-40 disabled:cursor-not-allowed'

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block text-[10px] text-white/50 uppercase tracking-wider">
      {label}
      <div className="mt-1 normal-case tracking-normal">{children}</div>
      {hint && <span className="mt-1 block normal-case tracking-normal text-white/60">{hint}</span>}
    </label>
  )
}
