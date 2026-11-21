# Pre-Live-test-A report

**Date:** 2026-11-21
**Branch:** `multiturn`, pushed to `origin/multiturn` at 7fad36a
**Scope:** the multi-turn build that will be tested live. Covers the state of each work package, how it was verified, what is still open, and what Live test A needs.

## 1. What is merged and pushed

Every work package below was read and approved by a separate reviewer before it was merged. Each reviewer also ran the full suite on SQLite and on Postgres, and changed code on purpose to check that the tests catch the change.

| WP | What it delivers | Review rounds |
|---|---|---|
| WP10 | CI gate: `cyber-rt gate` compares success-rate confidence intervals against a baseline (`canary-gate.yml`) | 2 |
| WP3 | Multi-turn engine: input is normalised and strictly re-validated at the boundary, production limits (rps≤1, parallel≤2, total≤300), kill switch and cancel, budget ledger, critical-monitor stop | 3 |
| WP11 | W&B Runs and Weave traces, all exports redacted (keyed hashes, linear-time regexes, curl/cookie/auth-header/provider-key rules) | 4 |
| WP7 | Job worker: a refused request ends the job as `refused`, one shared rate limiter per target that can only tighten, secret masking in events | 2 |
| WP4 | Planners: ScriptedPlanner with benign smoke packs; LLMPlanner refuses to start without the security owner's `prompts/planner.md` (that file is gitignored and dockerignored) | 1 |
| WP5 | Evaluation: monitors (canary, forbidden tool, secret pattern, PII), a judge that votes k=3 times, fail-closed verdict rules, findings lifecycle, calibration harness | 3 |
| WP8 | API v2: OIDC and API-key login, viewer/operator/admin roles, org isolation, transcripts redacted by default, audited raw reads, kill switch limited to platform admins | 2 |
| WP9 | Frontend aligned to WP8: CSRF, permission-gated UI, all SSE event types, Playwright smoke test with axe accessibility checks | 1 |

Test results on `multiturn` before the push:

| | Passed | Failures |
|---|---|---|
| Backend, SQLite | 1337 | 6 (see below) |
| Backend, Postgres | 1701 | 7 (see below) |
| Frontend | build and lint pass, vitest 21/21, Playwright 9/9 | axe: 0 violations |

The 6 SQLite failures (7 on Postgres) are all known:
- 5 are old failing tests in legacy code. The wiring branch deletes or fixes them.
- 1 is a test-isolation bug: a developer's local `.env` leaks into the tests. It fails on both databases, which is why Postgres shows one more. It is fixed on the wiring branch.

**History scrub before the push.** Two old WP11 commits contained W&B run files that included the W&B username. All `multiturn*` branches were rewritten to drop `cyber-redteam-foundry/wandb/**`.
- File contents at every branch tip are unchanged.
- No `wandb/` path or username is reachable from `multiturn`.
- Backup refs are kept locally under `refs/backup/prescrub/*`.

## 2. In flight, not yet pushed

- **Lead wiring (`multiturn-wiring`)**, under review. It wires the merged pieces into the real worker:
  - WP5 monitors and evaluation run per conversation, `verdict` SSE events are emitted, and `technique_results` are computed.
  - W&B/Weave is initialised at worker start, and target secrets are registered so they are masked.
  - The scripted planner can be selected with `PLANNER_FACTORY` (it is not the default; unset still fails closed).
  - `stopped_planner_guardrail` status, with the planner cost charged to the budget.
  - The real gate launcher.
  - The legacy HTTP adapter is deleted and the v1 flow is ported.
  - An end-to-end test: a canary leak causes a critical stop, an alert and a confirmed finding.
  - Results: 0 failing tests (SQLite 1386, Postgres 1780), and `ruff` is clean across the whole repo.
- **WP9b UI overhaul (`multiturn-wp9b`)**, being built:
  - design system with light and dark themes, console shell, page redesigns;
  - WCAG AA, 375 px mobile layout;
  - an XSS regression test;
  - axe checks in both themes.

## 3. Known open items (none block Live test A)

- **The rate limiter is per process.** Running N workers multiplies the effective rate by N. A limiter shared across workers is still TODO.
- **Judge spend is not charged to the campaign ledger**, because Backboard reports no price. It is bounded by conversations × k. For Live test A it is capped separately (see §4).
- **Before the LLM planner can ever be enabled**, three things are needed: a pinned `planner_prompt_sha256`, a scope classifier that can be configured, and the prompt itself from the security owner.
- **On SQLite, two concurrent sightings can lose a `seen_in_campaigns` entry.** Postgres is unaffected.
- **`/me` does not expose a platform-admin flag.** The kill-switch toggle therefore hides itself only after a 403.
- **There is no "test connection" endpoint**, so the button was removed from target onboarding.
- **Some tests are timing-sensitive and can flake under heavy load:** `test_env_kill_switch_stops_ten_conversations` and `test_curl_flag_regexes_stay_linear`.

## 4. Live test A: plan and readiness

Full plan: `docs/plan/live-test-plan.md`.

| Prerequisite | Status |
|---|---|
| Engine, worker, evaluation, scripted planner merged | Merged except the lead wiring, which is in review |
| `CANARY_ENCRYPTION_KEY` in `cyber-redteam-foundry/.env` | Set (generated, file mode 0600, gitignored) |
| `BACKBOARD_API_KEY` | **Empty: needed from the user** |
| `WANDB_API_KEY`, `WANDB_ENTITY` | **Empty: needed from the user** (`WANDB_PROJECT=canary-live`) |
| Spend cap | **$5 total**, approved by the user |
| Model choice | Lead picks after `cyber-rt doctor`. The judge uses a cheap, reliable model; the planner is scripted and makes no LLM calls |

The test runs in this order:
1. **Preflight.** `cyber-rt doctor`. Set the per-campaign `max_llm_cost_usd` well below $5, and keep a running total of spend.
2. **Onboard.** Register `fake_target`, running as its own HTTP server, and verify it through the real ownership flow.
3. **Smoke run.** Scripted smoke pack on the `always_safe` profile. Turns, Backboard judge verdicts and redacted W&B/Weave output must all appear.
4. **Critical stop.** `leaks_after_n_turns` profile. Expect a critical stop, an alert at the local webhook catcher and a confirmed finding.
5. **Production limits.** rps≤1, parallel≤2, total≤300, and `X-Canary-Campaign` on every request. An over-limit policy must be refused with nothing sent.
6. **Cancel and kill switch.** Each must stop the run within one turn.
7. **Resilience.** `flaky_500` and `slow` profiles. Kill the worker mid-run, then check it resumes.
8. **Gate.** Run against a baseline: an identical run passes, an injected regression fails.
9. **Leak sweep.** Zero hits for the target key or the Backboard key in logs, events, audit rows, W&B and Weave.

If total spend would exceed $5, the test stops and the user is told.
