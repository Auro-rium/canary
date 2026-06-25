import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  ShieldAlert, Zap, Play, Loader2, CheckCircle2, AlertTriangle,
  Activity, ShieldCheck, Cpu, Terminal, Layers, FileCode, XCircle,
  ChevronRight, Clock, Target, BarChart3
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { api } from './api';
import type { Incident, AnalysisReport, Intensity } from './types';

// ─── Constants ───────────────────────────────────────────────────────────────
const STRATEGIES = [
  'Prompt Injection', 'Data Exfiltration', 'Privilege Escalation', 'Tool Misuse'
] as const;
const GRAPH_NODES = ['strategist','attacker','evaluator','defender','reporter'] as const;

// ─── Toast System ────────────────────────────────────────────────────────────
type Toast = { id: string; msg: string; kind: 'ok' | 'err' | 'info' };

function Toasts({ items, onDismiss }: { items: Toast[]; onDismiss: (id: string) => void }) {
  return (
    <div className="fixed top-5 right-5 z-50 flex flex-col gap-2 pointer-events-none">
      <AnimatePresence>
        {items.map(t => (
          <motion.div key={t.id}
            initial={{ opacity: 0, x: 30 }} animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 30 }} transition={{ duration: 0.25 }}
            className={`pointer-events-auto flex items-center gap-2.5 px-4 py-3 rounded-lg border text-xs font-medium shadow-2xl backdrop-blur-sm min-w-[260px] cursor-pointer ${
              t.kind === 'ok'  ? 'bg-green-dim/10 border-green/30 text-green' :
              t.kind === 'err' ? 'bg-red/10 border-red/30 text-red' :
                                 'bg-card border-border text-slate-300'
            }`}
            onClick={() => onDismiss(t.id)}
          >
            {t.kind === 'ok' && <CheckCircle2 className="w-4 h-4 shrink-0" />}
            {t.kind === 'err' && <XCircle className="w-4 h-4 shrink-0" />}
            {t.kind === 'info' && <Activity className="w-4 h-4 shrink-0" />}
            <span className="flex-1">{t.msg}</span>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

// ─── Node Stepper (loading animation) ────────────────────────────────────────
function NodeStepper({ activeNode, label }: { activeNode: string | null; label: string }) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center gap-10 py-16">
      <div className="relative">
        <div className="w-20 h-20 rounded-full border-2 border-blue/20 flex items-center justify-center">
          <Cpu className="w-10 h-10 text-blue animate-spin" style={{ animationDuration: '3s' }} />
        </div>
        <div className="absolute -inset-2 rounded-full border border-blue/10 animate-ping" />
      </div>
      <div className="text-center space-y-2">
        <h2 className="text-lg font-light text-white tracking-wide">Executing State Graph</h2>
        <p className="mono text-slate-500 max-w-sm">{label}</p>
      </div>
      <div className="flex items-center gap-3 max-w-lg w-full px-6">
        {GRAPH_NODES.map((n, i, arr) => (
          <React.Fragment key={n}>
            <div className="flex flex-col items-center flex-1 gap-1.5">
              <div className={`w-9 h-9 rounded-full border-2 flex items-center justify-center text-[10px] font-bold transition-all duration-500 ${
                activeNode === n
                  ? 'bg-blue border-blue text-white shadow-[0_0_20px_rgba(91,141,239,0.5)] scale-110'
                  : 'bg-bg-surface border-border text-slate-600'
              }`}>{i + 1}</div>
              <span className={`text-[8px] font-bold uppercase tracking-[0.15em] transition-colors ${
                activeNode === n ? 'text-blue' : 'text-slate-600'
              }`}>{n}</span>
            </div>
            {i < arr.length - 1 && (
              <div className={`h-px flex-1 transition-colors ${
                activeNode === n ? 'bg-blue/50' : 'bg-border'
              }`} />
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

// ─── Report View ─────────────────────────────────────────────────────────────
function ReportView({ report, onApply, onBack }: { report: AnalysisReport; onApply: () => void; onBack: () => void }) {
  return (
    <div className="space-y-5 animate-in fade-in">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-3 label mb-1.5">
            <button onClick={onBack} className="flex items-center gap-1 text-blue hover:text-blue-bright transition-colors font-bold uppercase tracking-wider text-[10px]">
              &larr; Back
            </button>
            <span className="text-slate-600">|</span>
            <span>Incident Audit</span><span className="text-blue">• {report.id.slice(0, 8)}</span>
          </div>
          <h2 className="text-xl font-light text-white">{report.agent} <span className="opacity-30">→</span> {report.type}</h2>
        </div>
        <div className="flex gap-5 items-center">
          <div className="text-right">
            <div className="label opacity-60">Severity</div>
            <span className={`text-xs font-extrabold uppercase ${
              report.severity === 'Critical' || report.severity === 'High' ? 'text-red' : 'text-amber'
            }`}>{report.severity}</span>
          </div>
          <div className="w-px h-7 bg-border" />
          <div className="text-right">
            <div className="label opacity-60">Confidence</div>
            <span className="text-xs font-bold text-white mono">{report.confidence}%</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-5">
        {/* Left: Summary + Trace */}
        <div className="col-span-7 space-y-5">
          <div className="card p-5 space-y-4">
            <h3 className="label flex items-center gap-2"><Terminal className="w-3.5 h-3.5 text-amber" />Executive Summary</h3>
            <p className="mono text-slate-400 bg-bg-deep/60 p-3.5 rounded border border-border leading-relaxed">{report.summary}</p>
            <div className="grid grid-cols-2 gap-3">
              <div><div className="label mb-1">Root Cause</div><div className="mono text-slate-400 bg-bg-deep/40 p-3 rounded border border-border">{report.rootCause}</div></div>
              <div><div className="label mb-1">Mitigation</div><div className="mono text-slate-400 bg-bg-deep/40 p-3 rounded border border-border">{report.mitigation}</div></div>
            </div>
          </div>
          <div className="card p-5 space-y-3">
            <h3 className="label flex items-center gap-2"><Layers className="w-3.5 h-3.5 text-blue" />Attack Trace Log</h3>
            <div className="space-y-2 mono">
              {report.trace.map((s, i) => (
                <div key={i} className="flex gap-3 p-2.5 bg-bg-deep/40 rounded border border-border">
                  <span className="text-slate-600 shrink-0 w-12">{s.time}</span>
                  <span className={`uppercase font-bold shrink-0 w-14 ${
                    s.status === 'failed' ? 'text-red' : s.status === 'warning' ? 'text-amber' : 'text-green'
                  }`}>[{s.status}]</span>
                  <div className="flex-1 text-slate-400">
                    <span className="text-slate-300 font-semibold">{s.action}:</span> {s.details}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: YAML + Apply */}
        <div className="col-span-5 flex flex-col">
          <div className="card p-5 flex flex-col h-full gap-4">
            <div className="flex items-center justify-between">
              <h3 className="label flex items-center gap-2"><FileCode className="w-3.5 h-3.5 text-green" />Governance Patch</h3>
              <span className="text-[9px] mono text-slate-600">YAML</span>
            </div>
            <pre className="flex-1 bg-bg-deep p-4 rounded border border-border mono text-slate-400 overflow-auto whitespace-pre leading-relaxed select-all min-h-[200px]">
              {report.suggestedYaml || '# No patches generated'}
            </pre>
            {report.recommendations && report.recommendations.length > 0 && (
              <div>
                <div className="label mb-1.5">Recommendations</div>
                <ul className="space-y-1">
                  {report.recommendations.map((r, i) => (
                    <li key={i} className="mono text-slate-400 flex gap-2">
                      <ChevronRight className="w-3 h-3 text-blue shrink-0 mt-0.5" />{r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <button onClick={onApply} className="btn-green w-full flex items-center justify-center gap-2">
              <ShieldCheck className="w-4 h-4" />Apply Enforcement Patch
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Dashboard Overview ──────────────────────────────────────────────────────
function Dashboard({ incidents }: { incidents: Incident[] }) {
  const critical = incidents.filter(i => i.status === 'Critical').length;
  const blocked = incidents.filter(i => i.status === 'Blocked').length;
  const avg = incidents.length > 0
    ? Math.round(incidents.reduce((a, i) => a + i.riskScore, 0) / incidents.length) : 0;
  const trend = incidents.length > 1
    ? incidents.slice(-8).map((inc, i) => ({ time: `#${i + 1}`, score: inc.riskScore }))
    : [{ time: 'Start', score: 0 }, { time: 'Now', score: 0 }];

  const stats = [
    { label: 'Risk Index', value: avg, icon: Activity, color: 'text-blue' },
    { label: 'Blocked', value: blocked, icon: ShieldCheck, color: 'text-green' },
    { label: 'Critical', value: critical, icon: AlertTriangle, color: 'text-red' },
  ];

  return (
    <div className="space-y-5">
      <div className="card p-7 relative overflow-hidden">
        <div className="absolute -top-10 -right-10 opacity-[0.02] scale-[4] pointer-events-none">
          <ShieldCheck className="w-32 h-32" />
        </div>
        <div className="inline-flex px-2.5 py-0.5 bg-blue/10 border border-blue/20 text-[9px] font-bold text-blue uppercase tracking-[0.15em] rounded-full mb-3">
          Control Plane Active
        </div>
        <h2 className="text-2xl font-light text-white tracking-tight mb-2">Adversarial Governance Loop</h2>
        <p className="text-xs text-slate-500 max-w-lg leading-relaxed">
          Agent Canary attacks open-source AI agents with LLM-driven probes, evaluates guardrail resilience,
          and synthesizes runtime governance patches — all orchestrated by a LangGraph state machine.
        </p>
      </div>
      <div className="grid grid-cols-3 gap-4">
        {stats.map(s => (
          <div key={s.label} className="card p-5 flex flex-col justify-between h-28 hover:border-border-active transition-colors group">
            <div className="flex justify-between"><span className="label">{s.label}</span><s.icon className={`w-4 h-4 ${s.color} opacity-60 group-hover:opacity-100 transition-opacity`} /></div>
            <div className="text-2xl font-light text-white">{s.value}</div>
          </div>
        ))}
      </div>
      <div className="card p-5">
        <div className="flex justify-between items-center mb-4">
          <span className="label">Risk Telemetry</span>
          <span className="text-[9px] mono text-slate-600">{incidents.length} data points</span>
        </div>
        <div className="h-[200px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trend}>
              <defs>
                <linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#5b8def" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#5b8def" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis dataKey="time" stroke="#334155" fontSize={8} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} stroke="#334155" fontSize={8} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ backgroundColor: '#0b0f18', borderColor: 'rgba(255,255,255,0.06)', borderRadius: 6, fontSize: 10, fontFamily: 'monospace', color: '#cbd5e1' }} />
              <Area type="monotone" dataKey="score" stroke="#5b8def" strokeWidth={1.5} fill="url(#g)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ─── Main App ────────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════
export default function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Form
  const [targetUrl, setTargetUrl] = useState('http://localhost:9000/chat');
  const [strategy, setStrategy] = useState(STRATEGIES[0]);
  const [intensity, setIntensity] = useState<Intensity>('Medium');

  // Run state
  const [runStatus, setRunStatus] = useState<'idle' | 'running' | 'completed' | 'failed'>('idle');
  const [activeNode, setActiveNode] = useState<string | null>(null);
  const [progressLabel, setProgressLabel] = useState('');
  const pollRef = useRef<number | null>(null);

  // Toasts
  const [toasts, setToasts] = useState<Toast[]>([]);
  const toast = useCallback((msg: string, kind: Toast['kind'] = 'info') => {
    const id = crypto.randomUUID().slice(0, 8);
    setToasts(p => [...p, { id, msg, kind }]);
    setTimeout(() => setToasts(p => p.filter(t => t.id !== id)), 4500);
  }, []);

  // Backend connectivity
  const [backendOk, setBackendOk] = useState<boolean | null>(null);

  // ── Fetch incidents ──
  const fetchIncidents = useCallback(async () => {
    try {
      const data = await api.getIncidents();
      setIncidents(data);
    } catch (err: any) {
      toast(err.message || 'Failed to fetch incidents', 'err');
    }
  }, []);

  useEffect(() => {
    api.status().then(() => setBackendOk(true)).catch(() => setBackendOk(false));
    fetchIncidents();
    const iv = setInterval(fetchIncidents, 8000);
    return () => clearInterval(iv);
  }, [fetchIncidents]);

  // ── Select incident → load report ──
  const selectIncident = useCallback(async (inc: Incident) => {
    setSelectedId(inc.id);
    setReport(null);
    if (!inc.run_id) {
      toast('No run ID associated with this incident', 'info');
      return;
    }
    try {
      const data = await api.getAnalysis(inc.run_id);
      setReport(data);
    } catch (err: any) {
      toast(`Failed to load incident report: ${err.message}`, 'err');
    }
  }, [toast]);

  // ── Launch probe ──
  const handleLaunch = useCallback(async () => {
    if (runStatus === 'running') return;
    setRunStatus('running');
    setReport(null);
    setSelectedId(null);
    setActiveNode('strategist');
    setProgressLabel('Initializing LangGraph state machine...');

    try {
      const { run_id } = await api.createRun({
        target_id: targetUrl,
        strategy,
        intensity,
      });

      // Poll for completion
      const poll = window.setInterval(async () => {
        try {
          const run = await api.getRun(run_id);
          if (run.status === 'completed') {
            clearInterval(poll);
            pollRef.current = null;
            setActiveNode('reporter');
            setProgressLabel('Generating audit report...');

            try {
              const analysis = await api.getAnalysis(run_id);
              setReport(analysis);
              setSelectedId(run_id);
              toast(`Audit complete for ${targetUrl}`, 'ok');
            } catch {
              toast('Run completed but report generation failed', 'err');
            }
            setRunStatus('completed');
            setActiveNode(null);
            fetchIncidents();
          } else if (run.status === 'failed') {
            clearInterval(poll);
            pollRef.current = null;
            setRunStatus('failed');
            setActiveNode(null);
            toast('Probe execution failed', 'err');
          } else {
            // Update progress based on attack/patch counts
            const atks = run.attacks?.length ?? 0;
            const ptch = run.patches?.length ?? 0;
            if (atks === 0) {
              setActiveNode('strategist');
              setProgressLabel('Strategist selecting attack vectors...');
            } else if (ptch === 0 && run.status === 'running') {
              setActiveNode('attacker');
              setProgressLabel(`Attacker executing probe #${atks}...`);
            } else {
              setActiveNode('defender');
              setProgressLabel(`Defender applied ${ptch} patches...`);
            }
          }
        } catch { /* poll error, skip */ }
      }, 2000);
      pollRef.current = poll;
    } catch (err: any) {
      setRunStatus('idle');
      toast(err.message || 'Failed to start run', 'err');
    }
  }, [runStatus, targetUrl, strategy, intensity, toast, fetchIncidents]);

  // ── Apply patch ──
  const handleApply = useCallback(async () => {
    if (!report) return;
    try {
      await api.applyPolicy(report.id);
      toast('Governance policy applied', 'ok');
      fetchIncidents();
    } catch {
      toast('Failed to apply patch', 'err');
    }
  }, [report, toast, fetchIncidents]);

  // ═══════════════════════════════════════════════════════════════════════════
  // RENDER
  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <div className="flex h-screen w-screen overflow-hidden bg-bg-deep text-slate-300 font-sans">
      <Toasts items={toasts} onDismiss={id => setToasts(p => p.filter(t => t.id !== id))} />

      {/* ═══ LEFT SIDEBAR ═══ */}
      <aside className="w-[400px] bg-bg-surface border-r border-border flex flex-col shrink-0">
        {/* Brand */}
        <div className="px-5 py-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-md bg-blue/10 border border-blue/20 flex items-center justify-center">
              <ShieldAlert className="w-3.5 h-3.5 text-blue" />
            </div>
            <div>
              <h1 className="text-xs font-bold tracking-[0.15em] uppercase text-white">Agent Canary</h1>
              <p className="text-[9px] text-slate-600 mono">LangGraph Adversarial Engine</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-border">
            {backendOk === true && <><span className="w-1.5 h-1.5 rounded-full bg-green animate-pulse" /><span className="text-[8px] font-bold text-green uppercase tracking-widest">Online</span></>}
            {backendOk === false && <><span className="w-1.5 h-1.5 rounded-full bg-red" /><span className="text-[8px] font-bold text-red uppercase tracking-widest">Offline</span></>}
            {backendOk === null && <span className="text-[8px] text-slate-600">...</span>}
          </div>
        </div>
        {import.meta.env.VITE_DEMO_MODE === 'true' && (
          <div className="px-5 py-2 bg-amber/10 border-b border-amber/20 text-[9px] font-bold text-amber uppercase tracking-widest text-center">
            Demo Mode — data is not real
          </div>
        )}

        {/* Probe Launcher */}
        <div className="p-5 border-b border-border space-y-3">
          <h2 className="label flex items-center gap-1.5"><Zap className="w-3 h-3 text-blue" />Probe Launcher</h2>

          <div className="space-y-1">
            <label className="label">Target Endpoint</label>
            <input
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              placeholder="http://localhost:9000/chat"
              className="w-full bg-bg-deep border border-border rounded-md px-3 py-2 text-xs text-slate-300 mono focus:outline-none focus:border-blue/40 placeholder:text-slate-700"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="label">Strategy</label>
              <select value={strategy} onChange={e => setStrategy(e.target.value)}
                className="w-full bg-bg-deep border border-border rounded-md px-2 py-2 text-xs text-slate-300 focus:outline-none focus:border-blue/40">
                {STRATEGIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="space-y-1">
              <label className="label">Intensity</label>
              <div className="grid grid-cols-3 bg-bg-deep rounded-md border border-border p-0.5">
                {(['Low','Medium','High'] as Intensity[]).map(lvl => (
                  <button key={lvl} onClick={() => setIntensity(lvl)}
                    className={`py-1.5 text-[9px] font-bold rounded uppercase text-center transition-colors ${
                      intensity === lvl ? 'bg-blue text-white' : 'text-slate-600 hover:text-slate-400'
                    }`}>{lvl}</button>
                ))}
              </div>
            </div>
          </div>

          <button onClick={handleLaunch} disabled={runStatus === 'running' || backendOk === false}
            className="w-full btn-blue flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed">
            {runStatus === 'running'
              ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Running adversarial loop...</>
              : <><Play className="w-3 h-3 fill-current" />Launch Adversarial Probe</>
            }
          </button>
        </div>

        {/* Incident Feed */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="px-5 py-3 border-b border-border flex items-center justify-between shrink-0">
            <span className="label">Telemetry Feed</span>
            <span className="text-[9px] mono text-slate-600">{incidents.length}</span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {incidents.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-700 mono">
                No incidents recorded. Launch a probe to populate telemetry.
              </div>
            ) : incidents.map(inc => (
              <div key={inc.id} onClick={() => selectIncident(inc)}
                className={`px-5 py-3.5 border-b border-border cursor-pointer transition-colors ${
                  selectedId === inc.id ? 'card-active border-l-2 border-l-blue' : 'hover:bg-white/[0.01]'
                }`}>
                <div className="flex justify-between items-start mb-1.5">
                  <span className="text-[9px] mono text-slate-600">{inc.timestamp}</span>
                  <span className={inc.status === 'Critical' ? 'badge-red' : inc.status === 'Warning' ? 'badge-amber' : 'badge-green'}>
                    {inc.status}
                  </span>
                </div>
                <h3 className="text-xs font-medium text-white mb-0.5">{inc.agent}</h3>
                <div className="flex justify-between text-[10px] mono text-slate-500">
                  <span>{inc.type}</span>
                  <span>Risk: <span className={inc.riskScore > 50 ? 'text-red' : 'text-green'}>{inc.riskScore}</span></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </aside>

      {/* ═══ MAIN WORKSPACE ═══ */}
      <main className="flex-1 overflow-y-auto p-6">
        <div className="max-w-[1100px] mx-auto">
          {runStatus === 'running' ? (
            <NodeStepper activeNode={activeNode} label={progressLabel} />
          ) : report ? (
            <ReportView report={report} onApply={handleApply} onBack={() => { setReport(null); setSelectedId(null); }} />
          ) : (
            <Dashboard incidents={incidents} />
          )}
        </div>
      </main>
    </div>
  );
}
