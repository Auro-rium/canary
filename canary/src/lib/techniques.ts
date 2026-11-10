import type { AsiCode } from './contracts'

export interface Technique {
  id: string
  asiCode: AsiCode
  name: string
  description: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  estimatedDuration: string
}

// Slugs must match api.py's _TECHNIQUE_TO_STRATEGY mapping. asiCode is the
// backend taxonomy class (configs/asi_taxonomy.yaml) for that strategy;
// tests/test_asi_normalisation.py fails if the two drift.
export const TECHNIQUES: Technique[] = [
  {
    id: 'prompt-injection',
    asiCode: 'ASI01',
    name: 'Prompt Injection',
    description: 'Adversarial inputs overriding system instructions via user turn manipulation.',
    severity: 'CRITICAL',
    estimatedDuration: '~45s',
  },
  {
    id: 'memory-poisoning',
    asiCode: 'ASI05',
    name: 'Memory Poisoning',
    description: 'Corrupting agent long-term memory stores to alter future reasoning chains.',
    severity: 'CRITICAL',
    estimatedDuration: '~60s',
  },
  {
    id: 'tool-abuse',
    asiCode: 'ASI02',
    name: 'Tool & Plugin Abuse',
    description: 'Exploiting tool-call interfaces to invoke unintended external actions.',
    severity: 'HIGH',
    estimatedDuration: '~30s',
  },
  {
    id: 'privilege-escalation',
    asiCode: 'ASI01',
    name: 'Privilege Escalation',
    description: 'Manipulating agent context to exceed authorized permission boundaries.',
    severity: 'CRITICAL',
    estimatedDuration: '~50s',
  },
  {
    id: 'goal-hijacking',
    asiCode: 'ASI01',
    name: 'Goal Hijacking',
    description: 'Redirecting agent objective mid-session via indirect instruction channels.',
    severity: 'HIGH',
    estimatedDuration: '~40s',
  },
  {
    id: 'data-exfiltration',
    asiCode: 'ASI04',
    name: 'Data Exfiltration',
    description: 'Probing agent for leakage of system prompts, PII, or internal context.',
    severity: 'HIGH',
    estimatedDuration: '~35s',
  },
  {
    id: 'supply-chain',
    asiCode: 'ASI08',
    name: 'Supply Chain Attack',
    description: 'Injecting malicious content via third-party tool responses or RAG sources.',
    severity: 'HIGH',
    estimatedDuration: '~55s',
  },
  {
    id: 'denial-of-service',
    asiCode: 'ASI09',
    name: 'Agent DoS',
    description: 'Overloading agent reasoning loops via recursive or infinitely deferred tasks.',
    severity: 'MEDIUM',
    estimatedDuration: '~25s',
  },
]

export const TECHNIQUE_IDS = TECHNIQUES.map(t => t.id)
