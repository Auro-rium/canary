import { Link } from 'react-router-dom'
import type { DashboardOverview } from '../lib/types'

interface HeroProps { overview: DashboardOverview | null }

export default function Hero({ overview }: HeroProps) {
  const stats = overview ? [
    { value: String(overview.campaigns.targets), label: 'Targets assessed' },
    { value: String(overview.campaigns.total), label: 'Campaigns recorded' },
    { value: String(overview.open_findings.total), label: 'Open findings' },
  ] : [
    { value: '—', label: 'Targets assessed' }, { value: '—', label: 'Campaigns recorded' }, { value: '—', label: 'Open findings' },
  ]
  return <section className="relative min-h-screen overflow-hidden bg-black flex items-end">
    <video autoPlay muted loop playsInline className="absolute inset-0 h-full w-full object-cover animate-hero-video"><source src="/hero.mp4" type="video/mp4" /></video>
    <div className="absolute inset-0 bg-black/60" /><div className="absolute inset-x-0 bottom-0 h-[70%] bg-gradient-to-t from-black via-black/80 to-transparent" />
    <div className="relative z-10 w-full px-6 sm:px-10 md:px-16 lg:px-20 pb-14 md:pb-20 pt-32">
      <p className="text-white/50 text-[10px] tracking-[0.3em] uppercase mb-7">Autonomous red-team engine · authorized HTTP agents only</p>
      <div className="max-w-5xl grid lg:grid-cols-[1.2fr_0.8fr] gap-12 items-end">
        <div><h1 className="text-white font-bold uppercase leading-[0.88] tracking-[-0.06em] text-[clamp(3rem,9vw,6.5rem)]">Adversarial<br />Agent<br />Evaluation</h1>
          <p className="mt-7 text-white/60 max-w-xl text-sm leading-relaxed">Plan, execute, and review evidence-backed red-team campaigns against the AI agents you are authorized to test.</p>
          <div className="mt-8 flex flex-wrap gap-3"><Link to="/campaigns/new" className="px-6 py-3 bg-red-600 text-xs uppercase tracking-[0.15em] hover:bg-red-500">Run audit</Link><Link to="/campaigns" className="px-6 py-3 border border-white/30 text-xs uppercase tracking-[0.15em] hover:border-white/70">View campaigns</Link></div>
        </div>
        <div className="grid grid-cols-3 gap-5 border-t border-white/15 pt-6">{stats.map(stat => <div key={stat.label}><div className="text-2xl sm:text-3xl font-bold text-white">{stat.value}</div><div className="mt-1 text-white/40 text-[9px] uppercase tracking-[0.15em] leading-relaxed">{stat.label}</div></div>)}</div>
      </div>
    </div>
  </section>
}
