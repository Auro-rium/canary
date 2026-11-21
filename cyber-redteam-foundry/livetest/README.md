# Live test A harness

Runs the real Canary backend end to end against the repo's own benign `fake_target`
(`tests/fixtures/fake_target.py`, served over real HTTP on localhost), following
`docs/plan/live-test-plan.md` Live A steps 1-8. Real mode uses real Backboard (judge) and W&B with a
hard total spend cap of $5 (default run budget $4.50).

Run everything from `cyber-redteam-foundry/`:

```bash
cd ~/Documents/canary-wt/livetest/cyber-redteam-foundry     # or your checkout of this branch

# 1. Dry run: fake LLM, WANDB_MODE=disabled, no external calls, $0. Runs every step (~2.5 min).
uv run python -m livetest --dry-run

# 2. Real run (spends real money, capped). Needs BACKBOARD_API_KEY, WANDB_API_KEY, WANDB_ENTITY
#    set in ~/Documents/canary/cyber-redteam-foundry/.env. --yes is required.
uv run python -m livetest --yes

# Options
uv run python -m livetest --yes --judge-model openai/gpt-4o-mini --rate-in 0.00015 --rate-out 0.0006
uv run python -m livetest --yes --budget-usd 3.0          # smaller budget (max 5.0)
uv run python -m livetest --dry-run --steps 1,2,3          # a subset of steps
uv run python -m livetest --dry-run --keep-db              # keep database canary_live_a afterwards
```

Reports are written to `livetest/out/<run-id>/report/report.{md,json}` (gitignored), next to
`livetest/out/<run-id>/logs/` (API, worker, fake target logs) and `wandb/` (local W&B files).

## What it starts (and always tears down, including on Ctrl-C/SIGTERM)

- Postgres: reuses the running container `canary-pg-test` (never stopped or restarted) and creates a
  fresh database `canary_live_a`, runs `python -m cyberredteam.jobs.migrate` (alembic head and the
  procrastinate schema). The database is dropped at the end unless `--keep-db`.
- `cyber-rt auth ...` creates an org, an operator and an admin (API keys); the admin is the
  `CANARY_PLATFORM_ADMINS` entry, needed for the kill switch.
- API (`uvicorn cyberredteam.api:app`) and worker as separate processes in their own process groups.
  Worker env: `CANARY_ENV=dev`, `PLANNER_FACTORY=cyberredteam.planners.worker:scripted`,
  `WANDB_PROJECT=canary-live`, `WANDB_EXPORT_RAW_EVIDENCE=false`, ops webhook to the catcher,
  `TARGET_SAFETY_DIR` with the canary value, short heartbeat/stale times so a killed worker resumes.
- One `fake_target` HTTP server per target (profiles always_safe, leaks_after_n_turns, flaky_500, slow),
  each requiring an `X-Api-Key` that exists only in memory. They record request timing and headers.
- A local webhook catcher for the on-call and ops webhooks.
- Subprocess environments are built from scratch (only PATH/HOME are inherited) and run with an empty
  working directory, so no stray `.env` is picked up.

## Loopback and the SSRF guard

The guard refuses `127.0.0.1`/`localhost` by default. `security/ownership.py` now allows loopback
(and only loopback: not RFC1918, link-local or metadata) when `CANARY_ENV` is `dev` or `test` AND
`CANARY_ALLOW_LOOPBACK_TARGETS=1`. It never applies in production (tests in
`tests/test_loopback_allowance.py`). The harness sets both variables for its own processes only.

## Secrets

Real mode reads `~/Documents/canary/cyber-redteam-foundry/.env` by path at run time (`dotenv_values`,
the process environment is not modified) and passes values only to child process environments. Preflight
prints names and set/empty only. If `BACKBOARD_API_KEY`, `WANDB_API_KEY` or `WANDB_ENTITY` is empty,
it stops before starting anything. Reports are refused if they would contain a secret value.

## Preflight and model choice

The code exposes no Backboard model list, so the harness tries cheap judge candidates in order
(`openai/gpt-4o-mini`, `google/gemini-2.0-flash`, `anthropic/claude-haiku-4-5`, `openai/gpt-4.1-mini`) by
running `cyber-rt doctor` with `BACKBOARD_JUDGE_*` and `BACKBOARD_EVALUATOR_*` set to the candidate (doctor
pings the evaluator role), and takes the first that answers. Use `--judge-model provider/name` with
`--rate-in/--rate-out` (USD per 1k tokens) to force a model. The choice is recorded in the report.

## Spend guard

Backboard reports tokens, not prices, and the judge's spend is not charged to the campaign ledger
(`max_llm_cost_usd` only bounds planner spend, which is $0 for the scripted planner). The harness therefore
keeps its own running USD total, per step and overall:

- before a campaign is launched it reserves `conversations x k(3) x 2 (repair re-ask) x (input tokens x rate_in + output tokens x rate_out)`
  and aborts the run if that could cross the budget (default $4.50, hard cap $5.00; budgets above $5 are rejected);
- each campaign's `max_llm_cost_usd` is set to what is left of the budget (at most $0.50, at least $0.01);
- after a step it charges the estimate for conversations that ended, or the observed tokens from the
  worker log priced at the configured rates if larger;
- each `cyber-rt doctor` ping is charged $0.02.

Until the lead wiring merges, the worker never calls the judge: real spend is $0 and the report shows the
would-be estimate as `would_judge_if_wired` (counted for planning, not against the cap). In `--dry-run`
nothing is charged but the same accounting runs, so the abort logic is exercised and the total shows what a
real run would be estimated at.

## Wiring detection

`livetest/capabilities.py` checks the source tree (no imports) for `jobs/evaluation_wiring.py`,
`init_observability` in `jobs/worker.py` and `QueueCampaignLauncher` in `gate/launcher.py`. Assertions
that need a missing piece are reported as SKIP with the reason; everything else that does not hold is a
FAIL. After the wiring merges the assertions run without any harness change (not yet exercised against
the wiring branch's real judge/W&B).

## Steps

1. Onboard: register via API v2, verify through the real ownership flow (token published at
   `/.well-known/canary-verify.txt`); the DB is never touched for `verified`.
2. Smoke: always_safe, 5 conversations; turns persisted, events replayed; verdicts and W&B/Weave when wired.
3. Critical stop: leaks_after_n_turns; stopped_monitor, alert at the catcher, confirmed finding (when wired).
4. Production limits: rps<=1, parallel<=2, total<=300, `X-Canary-Campaign` on every request; over-limit
   policies refused with nothing sent.
5. Cancel and kill switch: each stops within one turn; operator refused (403), admin allowed; launches refused.
6. Resilience: flaky_500 (retry only non-2xx, budget per request), slow with a short timeout, and SIGKILL of
   the worker mid-run followed by resume.
7. Gate: `cyber-rt gate` against the step-2 baseline with the real launcher (identical passes, injected
   regression fails); skipped until the launcher merges. The synthetic `--demo` exit codes always run.
8. Leak sweep: every secret value (target keys, API keys, Backboard/W&B/encryption keys) is searched, from
   memory, in all logs, W&B files, every DB table (events, audit rows, turns, ...), API responses and webhook
   posts. Zero hits required; names only are reported.

Exit code: 0 pass, 1 fail, 2 preflight/usage, 3 aborted by the spend guard, 130 interrupted.
