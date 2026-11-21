import { TECHNIQUES, type Technique } from './techniques'

export interface TechniqueGroup { id: string; title: string; blurb: string; techniques: Technique[] }

// UI grouping only; the technique ids and ASI codes come from ./techniques (and the backend taxonomy).
const GROUPS: Array<{ id: string; title: string; blurb: string; ids: string[] }> = [
  { id: 'instructions', title: 'Instruction attacks', blurb: 'Override or redirect what the agent was told to do.', ids: ['prompt-injection', 'goal-hijacking', 'privilege-escalation'] },
  { id: 'tools-data', title: 'Tools and data', blurb: 'Misuse tool calls or pull out data the agent should keep.', ids: ['tool-abuse', 'data-exfiltration'] },
  { id: 'state-supply', title: 'Memory and supply chain', blurb: 'Poison what the agent remembers or retrieves.', ids: ['memory-poisoning', 'supply-chain'] },
  { id: 'availability', title: 'Availability', blurb: 'Exhaust the agent. Staging only: these are refused on production targets.', ids: ['denial-of-service'] },
]

export const TECHNIQUE_GROUPS: TechniqueGroup[] = GROUPS.map(group => ({
  id: group.id, title: group.title, blurb: group.blurb,
  techniques: group.ids.map(id => TECHNIQUES.find(t => t.id === id)).filter((t): t is Technique => !!t),
}))
