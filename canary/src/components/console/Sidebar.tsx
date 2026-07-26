import { useEffect, useState } from 'react'
import { useConsoleStore } from '../../store/useConsoleStore'
import { loadRunHistory } from '../../lib/db'

interface SidebarProps {
  onFindings?: () => void
  onRedTeam?: () => void
  onRunAudit?: () => void
}

const NAV_ITEMS: { label: string; key: keyof SidebarProps }[] = [
  { label: 'Red Team',  key: 'onRedTeam' },
  { label: 'Findings',  key: 'onFindings' },
  { label: 'Run Audit', key: 'onRunAudit' },
]

export default function Sidebar(props: SidebarProps) {
  const runHistory = useConsoleStore((s) => s.runHistory)
  const setRunHistory = useConsoleStore((s) => s.setRunHistory)
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    let cancelled = false
    loadRunHistory().then((history) => {
      if (!cancelled) {
        setRunHistory(history.sort((a, b) => b.campaign_id.localeCompare(a.campaign_id)))
        setLoaded(true)
      }
    })
    return () => { cancelled = true }
  }, [setRunHistory])

  return (
    <div className="flex flex-col h-full border-r border-white/10 w-[220px] shrink-0">
      <div className="px-4 py-3 border-b border-white/10">
        <span className="text-white/40 text-[10px] uppercase tracking-wider">Navigate</span>
      </div>
      <div className="flex flex-col border-b border-white/10">
        {NAV_ITEMS.map(({ label, key }) => (
          <button
            key={key}
            onClick={props[key]}
            className="text-left px-4 py-2.5 text-white/60 hover:text-white hover:bg-white/[0.03] text-[10px] uppercase tracking-wider transition-colors"
          >
            {label}
          </button>
        ))}
      </div>

      <div className="px-4 py-3 border-b border-white/10 shrink-0">
        <span className="text-white/40 text-[10px] uppercase tracking-wider">Run History</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {!loaded && (
          <div className="px-4 py-6 text-white/20 text-[9px] uppercase tracking-wider">Loading…</div>
        )}
        {loaded && runHistory.length === 0 && (
          <div className="px-4 py-6 text-white/20 text-[9px] uppercase tracking-wider">No runs yet</div>
        )}
        {runHistory.map((run) => (
          <div key={run.campaign_id} className="px-4 py-3 border-b border-white/[0.05]">
            <div className="text-white text-[11px] font-mono font-bold tracking-wider">{run.campaign_id}</div>
            <div className="text-white/30 text-[9px] mt-1 flex items-center gap-2">
              <span className="text-red-400">{run.critical_count} crit</span>
              <span>·</span>
              <span className="text-orange-400">{run.high_count} high</span>
            </div>
            <div className="text-white/20 text-[9px] mt-0.5">{run.total_findings} finding(s) · {run.duration_seconds}s</div>
          </div>
        ))}
      </div>
    </div>
  )
}
