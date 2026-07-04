import Navbar from '../Navbar'
import Sidebar from './Sidebar'
import ChatPanel from './ChatPanel'
import AgentGraphPanel from './AgentGraphPanel'
import { useConsoleStore } from '../../store/useConsoleStore'

interface ConsoleLayoutProps {
  onBack: () => void
  onFindings?: () => void
  onRedTeam?: () => void
  onDefenses?: () => void
  onRunAudit?: () => void
}

export default function ConsoleLayout({ onBack, onFindings, onRedTeam, onDefenses, onRunAudit }: ConsoleLayoutProps) {
  const phase = useConsoleStore((s) => s.phase)
  const agentStatuses = useConsoleStore((s) => s.agentStatuses)
  const activeEdge = useConsoleStore((s) => s.activeEdge)
  const campaignId = useConsoleStore((s) => s.campaignId)
  const targetUrl = useConsoleStore((s) => s.targetUrl)

  return (
    <div className="h-screen bg-black text-white font-mono flex flex-col overflow-hidden">
      <Navbar onLogoClick={onBack} onRunAudit={onRunAudit} onFindings={onFindings} onRedTeam={onRedTeam} onDefenses={onDefenses} />
      <div className="pt-16 md:pt-20 flex-1 flex overflow-hidden">
        <Sidebar onFindings={onFindings} onRedTeam={onRedTeam} onDefenses={onDefenses} onRunAudit={onRunAudit} />

        <div className="flex-1 min-w-0">
          <ChatPanel />
        </div>

        <div className="w-[380px] shrink-0 border-l border-white/10 flex flex-col">
          <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between shrink-0">
            <span className="text-white/40 text-[10px] uppercase tracking-wider">Agent Graph</span>
            <span className="text-white/25 text-[9px] font-mono">{campaignId}</span>
          </div>
          <div className="px-4 py-2 border-b border-white/10 shrink-0">
            <div className="text-white/20 text-[9px] uppercase tracking-wider">Target</div>
            <div className="text-white/50 text-[10px] font-mono break-all">{targetUrl.trim() || 'not set'}</div>
          </div>
          <div className="flex-1 flex items-center justify-center p-4 overflow-hidden">
            <AgentGraphPanel phase={phase} statuses={agentStatuses} activeEdge={activeEdge} />
          </div>
        </div>
      </div>
    </div>
  )
}
