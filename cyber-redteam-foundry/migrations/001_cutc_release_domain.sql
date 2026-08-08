-- CUTC 2026 release-domain migration.
-- SQLite local mode applies the equivalent additive columns in models.py.
-- PostgreSQL deployments should run this migration through their migration
-- runner before starting the API/worker.

ALTER TABLE releases ADD COLUMN IF NOT EXISTS candidate_endpoint TEXT;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS target_snapshot JSONB;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS configuration_snapshot JSONB;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS engine_snapshot JSONB;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS baseline_score DOUBLE PRECISION;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS candidate_score DOUBLE PRECISION;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS score_delta DOUBLE PRECISION;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS coverage JSONB;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS cancellation_requested BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS failure_code TEXT;
ALTER TABLE releases ADD COLUMN IF NOT EXISTS baseline_replay_run_id TEXT;

CREATE TABLE IF NOT EXISTS accepted_baselines (
  baseline_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  environment TEXT NOT NULL,
  release_id TEXT NOT NULL,
  accepted_by TEXT NOT NULL,
  acceptance_reason TEXT,
  target_snapshot JSONB,
  configuration_snapshot JSONB,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  accepted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  superseded_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS one_active_baseline_per_environment
  ON accepted_baselines (project_id, environment)
  WHERE active = TRUE;

CREATE TABLE IF NOT EXISTS attack_cases (
  attack_case_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  strategy TEXT NOT NULL,
  technique_id TEXT,
  payload TEXT NOT NULL,
  metadata_json JSONB,
  parent_branch_id TEXT,
  depth INTEGER NOT NULL DEFAULT 0,
  parent_evidence JSONB,
  mutation_rationale TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_executions (
  execution_id TEXT PRIMARY KEY,
  comparison_release_id TEXT NOT NULL,
  attack_case_id TEXT NOT NULL,
  subject_release_id TEXT,
  target_role TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'planned',
  response TEXT,
  deterministic_signals JSONB,
  evaluator_verdict TEXT,
  confidence TEXT,
  severity TEXT,
  evidence JSONB,
  finding_id TEXT,
  error TEXT,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_regressions (
  regression_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  baseline_release_id TEXT,
  candidate_release_id TEXT NOT NULL,
  attack_case_id TEXT NOT NULL,
  finding_id TEXT,
  classification TEXT NOT NULL,
  baseline_verdict TEXT,
  candidate_verdict TEXT,
  baseline_evidence JSONB,
  candidate_evidence JSONB,
  severity TEXT,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS release_events (
  event_id TEXT PRIMARY KEY,
  release_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  stage TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
