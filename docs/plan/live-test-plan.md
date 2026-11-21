# Full live test plan

The goal is to run Canary end to end against real services and confirm that it behaves correctly and that its safety controls hold. The only target is the in-repo `fake_target`, which we own, and the content is benign.

## Why it runs in two stages

As of 2026-11-19 the full test cannot run on `multiturn`:
- **No planner.** Nothing can drive a conversation yet.
  - `PLANNER_FACTORY` fails closed by design, because `prompts/planner.md` belongs to the security owner and is out of scope.
  - The only planner allowed here is WP4's ScriptedPlanner with its benign smoke packs, and WP4 hasn't been built.
- **Missing work packages.** WP5 (`evaluate_conversation`), WP7 (under review) and WP8 (API v2 + auth) haven't merged.
- **Lead wiring:** done on `multiturn-wiring` (worker observability, `register_target_secrets`, monitors, evaluation, the real WP10 `CampaignLauncher`, `HttpTargetAdapter` deleted). Still open: `SqlTargetStore` at `api.py:72-73` (WP8).

## Live A: backend (after WP7, WP4, WP5 and the lead wiring)

### Stack
- Real Postgres (`canary-pg-test`, or a fresh compose DB).
- The API and the worker, run as separate processes.
- `fake_target` running as its own HTTP server on localhost.
- Backboard is real.
- W&B/Weave are real, in a dedicated project. Raw evidence export is OFF.
- The on-call and ops webhook URLs point at a local catcher, so no real pager fires.

### Preflight
- `cyber-rt doctor` passes and the Backboard model IDs are confirmed.
- `max_llm_cost_usd` is set small (≤ $2 for the whole run).

### Steps
1. **Onboard the target.** Register `fake_target` through the real ownership flow and verify it. Never set `verified=True` directly in the DB.
2. **Smoke run.** Run a ScriptedPlanner smoke pack on the `always_safe` profile. Expect:
   - Turns persist one by one, the judge calls go to Backboard, and verdicts are stored.
   - A W&B run and Weave traces appear, and they are redacted.
3. **Critical stop.** Run on the `leaks_after_n_turns` profile. Expect a critical monitor hit, the conversation stopped, an alert received at the catcher, and a finding created.
4. **Production limits.** Use a production-environment target and observe: rps≤1, at most 2 conversations at once, at most 300 requests in total, and every request carrying the `X-Canary-Campaign` header. A policy that exceeds these limits is refused, and no request is sent.
5. **Cancel and kill switch.** Cancel a run and confirm it stops within one turn. Flip the kill switch and confirm every active conversation stops, and that new launches are refused.
6. **Resilience.** Use the `flaky_500` and `slow` profiles. Expect retries only on non-2xx responses, and budget charged per HTTP request. Kill the worker in the middle of a run, and confirm the reaper and resume complete the campaign.
7. **Gate.** Run `cyber-rt gate` with the real launcher against a baseline. Expect a pass on an identical run and a fail when a regression is injected.
8. **Leak sweep.** Grep the logs, events, audit rows, W&B and Weave exports for the target key and the Backboard key. Zero hits allowed.

## Live B: UI (after WP8 and WP9/WP9b)

Run the Playwright smoke test against the same stack: log in, onboard, launch, live grid, transcript, cancel, triage, report download. Also run the axe check and grep the built bundle.

## Credentials the user must provide (never committed)

Put these in `cyber-redteam-foundry/.env`. The `.env` file is gitignored; check that before adding anything.
- `BACKBOARD_API_KEY`, plus `BACKBOARD_LLM_PROVIDER` and `BACKBOARD_MODEL_NAME` (confirm them with `cyber-rt doctor`).
- `WANDB_API_KEY`, plus the W&B entity and project to use.
- `CANARY_ENCRYPTION_KEY` (any fresh key, used only for the test DB).
- OIDC client credentials, or an API key, for Live B.
