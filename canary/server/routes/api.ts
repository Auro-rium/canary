import { Router } from 'express';
import { randomUUID } from 'crypto';
import { runs, incidents } from '../store.js';
import { analyzeWithBedrock } from '../services/bedrock.js';
import { config } from '../config.js';
import type { Run, Incident } from '../types.js';

export const router = Router();

// Health check
router.get('/status', (_req, res) => {
  res.json({ status: 'ok', version: '1.0.0-phase1' });
});

// Create a new run
router.post('/runs', async (req, res) => {
  const { target_id, strategy = 'Prompt Injection', intensity = 'Medium' } = req.body ?? {};
  if (!target_id) {
    res.status(400).json({ error: 'target_id is required' });
    return;
  }

  const token = req.headers.authorization!.split(' ')[1];
  const run_id = randomUUID();
  const run: Run = {
    run_id,
    target_id,
    strategy,
    intensity,
    status: 'pending',
    start_time: null,
    end_time: null,
    attacks: [],
    patches: [],
    token,
  };
  runs.set(run_id, run);

  // Fire-and-forget: proxy to downstream LangGraph service
  (async () => {
    try {
      run.status = 'running';
      run.start_time = new Date().toISOString();

      const downstream = await fetch(`${config.DOWNSTREAM_URL}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ run_id, target_id, strategy, intensity }),
      });

      if (downstream.ok) {
        const result = await downstream.json() as any;
        run.attacks = result.attacks ?? [];
        run.patches = result.patches ?? [];
        run.status = 'completed';
      } else {
        run.status = 'failed';
      }
    } catch {
      run.status = 'failed';
    } finally {
      run.end_time = new Date().toISOString();

      // Record incident
      if (run.attacks.length > 0) {
        const successCount = run.attacks.filter(a => a.success).length;
        const maxScore = Math.max(...run.attacks.map(a => a.score ?? 0), 0);
        const incident: Incident = {
          id: randomUUID(),
          run_id: run.run_id,
          timestamp: run.end_time,
          agent: target_id,
          type: strategy,
          riskScore: Math.round(maxScore),
          status: maxScore > 70 ? 'Critical' : maxScore > 40 ? 'Warning' : 'Blocked',
          details: `${successCount}/${run.attacks.length} attacks succeeded`,
        };
        incidents.unshift(incident);
      }
    }
  })();

  res.json({ run_id, status: 'pending' });
});

// Get run status
router.get('/runs/:id', (req, res) => {
  const run = runs.get(req.params.id);
  if (!run) { res.status(404).json({ error: 'Run not found' }); return; }

  const token = req.headers.authorization!.split(' ')[1];
  if (run.token !== token) { res.status(403).json({ error: 'Forbidden: run belongs to a different token' }); return; }

  const { token: _omit, ...safe } = run;
  res.json(safe);
});

// Get analysis report (calls Bedrock)
router.get('/runs/:id/analysis-report', async (req, res) => {
  const run = runs.get(req.params.id);
  if (!run) { res.status(404).json({ error: 'Run not found' }); return; }

  const token = req.headers.authorization!.split(' ')[1];
  if (run.token !== token) { res.status(403).json({ error: 'Forbidden' }); return; }

  if (run.status !== 'completed') {
    res.status(409).json({ error: `Run is not complete (status: ${run.status})` });
    return;
  }

  // Return cached report if available
  if (run.analysisReport) {
    res.json(run.analysisReport);
    return;
  }

  try {
    const report = await analyzeWithBedrock({
      agent: run.target_id,
      strategy: run.strategy,
      intensity: run.intensity,
      attacks: run.attacks,
    });
    run.analysisReport = report;
    res.json(report);
  } catch (err: any) {
    console.error('Bedrock analysis failed:', err.message);
    res.status(502).json({ error: `Analysis failed: ${err.message}` });
  }
});

// Apply policy patch
router.post('/runs/:id/apply', (req, res) => {
  const run = runs.get(req.params.id);
  if (!run) { res.status(404).json({ error: 'Run not found' }); return; }

  const token = req.headers.authorization!.split(' ')[1];
  if (run.token !== token) { res.status(403).json({ error: 'Forbidden' }); return; }

  if (!run.analysisReport) {
    res.status(409).json({ error: 'No analysis report to apply — generate report first' });
    return;
  }

  // Mark patches as applied (Phase 1: record only; actual guardrail deployment is Phase 4)
  run.patches = run.patches.map(p => ({ ...p, applied: true }));

  res.json({ status: 'applied', message: 'Governance patch recorded. Guardrail deployment scheduled for Phase 4.' });
});

// List incidents
router.get('/incidents', (req, res) => {
  const token = req.headers.authorization!.split(' ')[1];
  // Return only incidents from runs owned by this token
  const tokenRunIds = new Set(
    [...runs.values()].filter(r => r.token === token).map(r => r.run_id)
  );
  res.json(incidents.filter(i => tokenRunIds.has(i.run_id)));
});
