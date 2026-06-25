export interface Run {
  run_id: string;
  target_id: string;
  strategy: string;
  intensity: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  start_time: string | null;
  end_time: string | null;
  attacks: AttackDetail[];
  patches: PatchDetail[];
  token: string; // the API token that created this run — for scope enforcement
  analysisReport?: AnalysisReport;
}

export interface AttackDetail {
  id: number;
  attempt_number: number;
  strategy_type: string;
  prompt: string;
  response: string;
  success: boolean;
  severity: string;
  score: number;
  indicators: string;
  timestamp: string | null;
}

export interface PatchDetail {
  id: number;
  patch_id: string;
  patch_type: string;
  target_component: string;
  original_config: string;
  patched_config: string;
  diff: string;
  applied: boolean;
  retest_passed: boolean;
}

export interface TraceStep {
  time: string;
  action: string;
  status: 'passed' | 'failed' | 'warning';
  details: string;
}

export interface AnalysisReport {
  id: string;
  agent: string;
  type: string;
  intensity: string;
  summary: string;
  rootCause: string;
  businessImpact: string;
  policyGap: string;
  mitigation: string;
  confidence: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  trace: TraceStep[];
  attackPayload: string;
  rawOutput: string;
  suggestedYaml?: string;
  recommendations?: string[];
}

export interface Incident {
  id: string;
  run_id: string;
  timestamp: string;
  agent: string;
  type: string;
  riskScore: number;
  status: 'Critical' | 'Warning' | 'Blocked';
  details: string;
}
