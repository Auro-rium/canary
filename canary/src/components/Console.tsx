import type { ReactNode } from 'react'

export function PageHeader({ eyebrow, title, children }: { eyebrow: string; title: string; children?: ReactNode }) {
  return <header className="px-6 sm:px-10 md:px-16 lg:px-20 py-10 border-b border-white/10"><p className="text-white/30 text-[10px] tracking-[0.28em] uppercase">// {eyebrow}</p><div className="mt-4 flex flex-wrap gap-4 items-end justify-between"><h1 className="text-2xl sm:text-3xl uppercase tracking-[0.08em] font-light">{title}</h1>{children}</div></header>
}

export function Metric({ label, value, tone = 'default' }: { label: string; value: string | number; tone?: 'default' | 'danger' | 'warning' }) {
  const color = tone === 'danger' ? 'text-red-400' : tone === 'warning' ? 'text-orange-400' : 'text-white'
  return <div className="border border-white/10 bg-white/[0.02] px-4 py-3 min-w-[140px]"><div className="text-white/30 text-[9px] uppercase tracking-[0.15em]">{label}</div><div className={`mt-1 text-lg ${color}`}>{value}</div></div>
}

export function StatusBadge({ status }: { status: string }) {
  const tone = status === 'completed' || status === 'open' ? 'text-red-400 border-red-600/30 bg-red-950/20' : status === 'running' ? 'text-yellow-300 border-yellow-500/30 bg-yellow-950/20' : status === 'failed' ? 'text-red-300 border-red-600/40 bg-red-950/40' : 'text-white/50 border-white/15'
  return <span className={`inline-flex border px-2 py-1 text-[9px] uppercase tracking-[0.13em] ${tone}`}>{status.replace(/_/g, ' ')}</span>
}

export function ErrorNotice({ message }: { message: string }) { return <div role="alert" className="border border-red-600/30 bg-red-950/20 px-4 py-3 text-red-300 text-xs">{message}</div> }
export function EmptyState({ children }: { children: ReactNode }) { return <div className="border border-dashed border-white/15 p-10 text-center text-white/35 text-xs uppercase tracking-[0.15em]">{children}</div> }
