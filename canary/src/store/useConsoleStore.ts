import { create } from 'zustand'
import type { Phase, AgentStatus, LogEntry, FindingPayload, CompletePayload } from '../lib/types'

export interface ChatMessage {
  id: string
  role: 'user' | 'system'
  kind: 'text' | 'log' | 'finding' | 'report' | 'error' | 'help' | 'list'
  content: string
  timestamp: number
}

let edgeTimer: ReturnType<typeof setTimeout> | null = null

interface ConsoleStore {
  targetUrl: string
  selectedTechniques: string[]
  campaignId: string
  phase: Phase
  agentStatuses: Record<string, AgentStatus>
  activeEdge: string | null
  logs: LogEntry[]
  findings: FindingPayload[]
  report: CompletePayload | null
  chatMessages: ChatMessage[]
  runHistory: CompletePayload[]
  lastConfig: { targetUrl: string; techniques: string[] } | null

  setTargetUrl: (url: string) => void
  setTechniques: (ids: string[]) => void
  setLastConfig: (cfg: { targetUrl: string; techniques: string[] }) => void
  newCampaignId: () => void
  setPhase: (phase: Phase) => void
  updateAgent: (id: string, status: AgentStatus) => void
  fireEdge: (key: string) => void
  appendLog: (level: LogEntry['level'], message: string) => void
  addFinding: (f: FindingPayload) => void
  setReport: (r: CompletePayload | null) => void
  pushMessage: (m: Omit<ChatMessage, 'id' | 'timestamp'>) => void
  resetCampaign: () => void
  setRunHistory: (h: CompletePayload[]) => void
  addRunHistory: (r: CompletePayload) => void
}

const makeCampaignId = () => `RX-${Math.floor(Math.random() * 900000 + 100000)}`

export const useConsoleStore = create<ConsoleStore>((set) => ({
  targetUrl: '',
  selectedTechniques: [],
  campaignId: makeCampaignId(),
  phase: 'idle',
  agentStatuses: {},
  activeEdge: null,
  logs: [],
  findings: [],
  report: null,
  chatMessages: [],
  runHistory: [],
  lastConfig: null,

  setTargetUrl: (url) => set({ targetUrl: url }),
  setTechniques: (ids) => set({ selectedTechniques: ids }),
  setLastConfig: (cfg) => set({ lastConfig: cfg }),
  newCampaignId: () => set({ campaignId: makeCampaignId() }),
  setPhase: (phase) => set({ phase }),

  updateAgent: (id, status) =>
    set((s) => ({ agentStatuses: { ...s.agentStatuses, [id]: status } })),

  fireEdge: (key) => {
    set({ activeEdge: key })
    if (edgeTimer) clearTimeout(edgeTimer)
    edgeTimer = setTimeout(() => {
      set({ activeEdge: null })
      edgeTimer = null
    }, 1200)
  },

  appendLog: (level, message) => {
    const timestamp = new Date().toISOString().slice(11, 19)
    set((s) => ({ logs: [...s.logs, { timestamp, level, message }] }))
  },

  addFinding: (f) => set((s) => ({ findings: [...s.findings, f] })),
  setReport: (r) => set({ report: r }),

  pushMessage: (m) =>
    set((s) => ({
      chatMessages: [
        ...s.chatMessages,
        { ...m, id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, timestamp: Date.now() },
      ],
    })),

  resetCampaign: () =>
    set({
      phase: 'idle',
      logs: [],
      findings: [],
      report: null,
      agentStatuses: {},
      activeEdge: null,
      campaignId: makeCampaignId(),
    }),

  setRunHistory: (h) => set({ runHistory: h }),
  addRunHistory: (r) => set((s) => ({ runHistory: [r, ...s.runHistory.filter(x => x.campaign_id !== r.campaign_id)] })),
}))
