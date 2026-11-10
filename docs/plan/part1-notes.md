# Canary context notes, part 1 (from read agents 1, 3, 4, 6, 9)

Repo: ~/Documents/canary (github.com/Auro-rium/canary). Line refs are relative to the repo root or to `cyber-redteam-foundry/src/cyberredteam/`.

## Overview
- Autonomous red-team platform for **authorized HTTP AI agents**. NVIDIA Nemotron generates attacks against a real target, then evaluates the target's actual replies. Findings are triaged by humans; nothing is auto-fixed.
- Two services:
  - `cyber-redteam-foundry/`: Python 3.11, FastAPI + LangGraph, SQLite.
  - `canary/`: React 19 + TypeScript + Vite + Tailwind dashboard, served by Vercel or nginx.
- Also `explainer/explainer.html`, a static case-file page (agent-canary-explainer.vercel.app).
- Demo target: the separate CompanyAgent repo, a LangChain + Backboard agent at `POST http://13.201.9.115/chat`. The shared AWS backend `i-0120dbe4036377c33` (ap-south-1, 3.108.23.172) has been **terminated**.
- Sample campaign `0017b2c0` (2026-08-11): 24 attempts, 3 confirmed findings, 49 LLM calls, 184,529 tokens (115,536 in / 68,993 out).

## Deploy
- **Docker compose:**
  - `redteam-backend`: uvicorn on :8001 (`--timeout-keep-alive 300`), `RUNNING_IN_DOCKER=true` (rewrites localhost to `host.docker.internal`), volumes `runs/` and `reports/`, healthcheck `/health`.
  - `canary-frontend`: nginx on 8000:80.
- **AWS override:** the backend listens on 80:8001; the frontend sits behind the `local-ui` profile.
- **Frontend reaching the backend:**
  - Vite dev: `/api` proxied to `localhost:8001`, 300 s timeout.
  - nginx: `/api/` → `redteam-backend:8001/api/`, buffering off, 300 s timeouts, SSE-friendly.
  - Vercel: `api/[...path].js` catch-all plus 10 re-export files. It forwards to `${CANARY_API_URL}/api/${path}`, injects `Authorization: Bearer ${CANARY_API_TOKEN}` server-side, allows GET/HEAD/POST/PUT, and streams the body back. It returns 503 if not configured and 502 on error. No `maxDuration` is set.
- **Browser client `canary/src/lib/api.ts`:**
  - `API_BASE = VITE_API_URL ?? ''`.
  - Optional `VITE_API_TOKEN` is sent as a bearer token.
  - Errors throw `ApiError(detail)`.
  - SSE is read with fetch + a stream reader, splitting `data:` lines.
- **Security:**
  - Docker mode bakes `VITE_API_TOKEN` (= `API_SECRET_KEY`) into the public JS bundle.
  - Port 8001 is exposed directly.
  - The Vercel proxy lets anonymous users POST campaigns and PUT finding status.
  - The token compare uses `!=`, not a constant-time check.
  - CORS is `*`.

## Frontend → backend routes (all 13 exist in the backend)
| Method | Path | api.py line |
|---|---|---|
| GET | /api/dashboard/overview | L241 |
| GET | /api/targets | L330 |
| GET | /api/runs | L293 |
| GET | /api/runs/{id} | L437 |
| GET | /api/runs/{id}/report-markdown | L626 |
| GET | /api/runs/{id}/findings | L737 |
| GET | /api/targets/{t}/coverage | L719 |
| GET | /api/targets/{t}/trends | L728 |
| GET | /api/findings | L652 |
| GET | /api/findings/{id} | L675 |
| GET | /api/findings/{id}/attempts | L686 |
| PUT | /api/findings/{id}/status | L695 |
| POST | /api/campaigns/run (SSE) | L897 |

Backend-only routes the frontend never calls: `/api/status`, `POST /api/runs`, `/api/runs/{id}/analysis-report`, `/api/open-findings`, `/api/incidents`, and `/health` (unauthenticated middleware).

## Env vars
- **Backend `Settings` (pydantic-settings, `.env`):**
  - `NVIDIA_API_KEY` (required), `NVIDIA_BASE_URL`
  - `API_SECRET_KEY`: bearer token; if unset the API returns 503 (fails closed)
  - `ALLOWED_TARGETS`, `REQUIRE_TARGET_ALLOWLIST`
  - `TARGET_MODE=http`, `TARGET_ENDPOINT`, `TARGET_API_KEY`
  - `LOG_LEVEL`, `LOG_FILE`, `DB_PATH=runs/redteam.db`, `REPORT_OUTPUT_DIR`, `REPORT_FORMAT`
  - `MAX_RETRIES=3`, `MAX_CONCURRENT_RUNS=3`, `TIMEOUT_SECONDS=30`, `DETERMINISTIC_SEED=42`
- **Frontend:** `VITE_API_URL`, `VITE_API_TOKEN` (build args); `CANARY_API_URL`, `CANARY_API_TOKEN` (Vercel, server-side).
- **Optional:** LangSmith `LANGCHAIN_*`.
- `.env.example` is stale: it still has the Bedrock/`AWS_REGION` block and no `NVIDIA_*`.

## Data model (`schemas.py`)
- **StrategyType** (13 values): prompt_injection, indirect_injection, jailbreak, tool_misuse, retrieval_poisoning, memory_poisoning, sensitive_data_exposure, workflow_manipulation, agent_handoff_corruption, authorization_boundary, instruction_hierarchy, context_isolation, privilege_escalation.
- **AttackSeverity:** critical, high, medium, low, info.
- **RunConfig:** `{run_id, target_id, strategy_types[], max_attempts=5, timeout_seconds=30, seed, description, target_headers{}, target_request_template?, target_response_path?}`
- **AttackResult:** `{run_id, target_id, attempt_number, strategy_type, prompt, response, success, severity, score 0..1, score_threshold=.5, finding_id, indicators{}, timestamp, error, technique_id, capability_type, depth, mutation_of_parent, branch_id, iteration}`
- **AttackBranch** (dataclass, Send payload): `{branch_id, capability_type, technique_id (ASIxx), technique_spec, target_metadata{name, declared_purpose, observability_level:"black_box"}, depth=0, attempt_budget_remaining, parent_evidence=None}`
- **RedTeamReport:** `{run_id, target_id, start/end, total/successful_attacks, attack_results, severity_distribution, success_rate, recommendations, assumptions, evidence_files, narratives}`

## SQLite `runs/redteam.db`
- No foreign keys; tables join by `run_id` / `finding_id`. Light migrations add columns via `ALTER TABLE`.
- Tables:
  - **runs**: run_id, target_id, start/end, totals, success_rate, status, error
  - **attacks**: id, run_id, target_id, attempt_number, strategy_type, prompt, response, success 0/1, severity, score, score_threshold, finding_id, indicators JSON, timestamp, error
  - **llm_calls**: run_id, agent_name, deployment, latency, input/output hash, prompt/completion tokens
  - **findings**: finding_id PK, target_id, component, strategy, asi_class, atlas_technique, severity, status (default open), first/last_seen_run, seen_in_runs JSON, embedding JSON (384 floats), trace_s3_uri, created/updated
  - **evaluator_verdicts**: verdict_id, finding_id, run_id, attempt_number, deterministic/llm_judge/consensus score, threshold_used, verdict, confidence, rationale, inconclusive_reason, asi_class_suggested, verdict_path
  - **attack_traces**: trace_id, attempt_id, finding_id, run_id, adversarial_input, tool_calls_observed, target_response
- LangGraph checkpoints are stored separately in `runs/checkpoints.db`; `thread_id` = `run_id`.
- **Finding upsert:** a new finding is embedded with all-MiniLM-L6-v2. At cosine ≥ 0.92 against an open finding it only *warns* about a duplicate. An existing finding gets the run appended to `seen_in_runs` and its severity can only increase.
- **Status transitions:** `open` can move to wont_fix, false_positive or inconclusive; `inconclusive` can move to open, wont_fix or false_positive. `wont_fix` and `false_positive` are terminal and require `reviewer_id` + `rationale`, which are validated but not stored.

## CLI `cyber-rt` (Typer)
- `init`
- `run --target-id URL --strategies a,b --max-attempts 5 --max-iterations 3 --seed`
- `list-strategies`
- `status`
- `graph [--save]` (Mermaid)
- `doctor` (checks the NVIDIA key and does a live ping)
- `server --host --port` (uvicorn, reload)

## LLM layer
- NVIDIA NIM only, via `ChatOpenAI(base_url=https://integrate.api.nvidia.com/v1, temperature=0.7, max_tokens=8192)`.
  - Every agent uses `nvidia/nemotron-3-ultra-550b-a55b` (`configs/models.yaml`).
  - The file `llm/bedrock.py` is misnamed; it contains the `ObservableLLM` wrapper. `azure_openai.py` is a shim.
  - A missing key raises an error; there is no mock fallback.
- **Chain:** `SystemMessage(prompts/<agent>.md) + "{user_message}" | llm.with_structured_output(PydanticSchema, include_raw=True)`.
  - `.with_retry` on `openai.APIError` / `ClientError`, 3 attempts, exponential jitter.
  - A parse error is raised immediately: no repair, no re-ask.
  - Tokens come from `usage_metadata` and are saved to `llm_calls` with sha256[:16] input/output hashes. Cost is not tracked.

## LangGraph (graph.py / nodes.py / state.py / orchestrator.py)
```
START → strategist (log only, NO LLM)
      → dispatch_attacker_branches: Send("attacker_branch", payload) per strategy (cap MAX_PARALLEL_BRANCHES=12)
      → attacker_branch ×N in parallel (1 LLM payload + 1 HTTP target call each)
      → evaluator (barrier; sequential evaluate_batch over this iteration's results)
      → should_iterate: (iteration+1 < max_iterations AND any success so far) ? strategist : reporter
      → reporter → END
```
- **RedTeamState fields:**
  - Set at start: run_id, target_id, description, seed, status, target_headers, target_request_template, target_response_path, strategies, max_iterations, max_attempts_per_strategy, timeout_seconds (unused)
  - Loop control: iteration, current_strategy, should_continue_iterating, vulnerability_found
  - Results and output: **attack_results (operator.add)**, scores, report_paths{markdown,json}
  - Bookkeeping: graph_visualization, start/end_time, error, **log_messages (operator.add)**
- Re-iterations send the same strategies again at depth 0; there is no adaptive mutation in practice.
- **Budgets:**
  - API intensity Low/Med/High maps to iterations 1/2/3 and attempts 2/4/5.
  - The campaign endpoint uses iterations=3 and attempts=max(4, 2×#strategies).
  - `attempts` is prompt text only; each branch makes exactly one attack.
- **Orchestrator.run():**
  1. `save_run_start`
  2. `graph.invoke(state, thread_id=run_id)`, synchronous
  3. `_persist_artifacts`: attacks, traces, verdicts, and an upsert for each finding with a confirmed or unconfirmed verdict
  4. `update_run_complete`
- **Concurrency:** API runs each campaign in a daemon thread, capped at `MAX_CONCURRENT_RUNS`, otherwise HTTP 429.

## Agent JSON formats
### Attacker → `AttackerOutput`
```json
{"status":"OK|ATTACKER_REFUSED","capability_type":"echo","technique_id":"ASIxx echo","depth":0,
 "payload":"exact text sent to target ('' if refused)","rationale":"1-3 sentences",
 "mutation_of_parent":null,"refusal_reason":null}
```
- **User message:** capability_type, technique_id, technique_spec, target_metadata JSON, depth, attempt_budget_remaining, parent_evidence, plus "generate payload yourself".
- **Prompt rules:** stay in scope; a realistic business persona; 3–6 sentences; banned keywords (OVERRIDE, IGNORE, JAILBREAK, BYPASS, ADMIN_MODE…); hard-refusal categories (CSAM, bio/chem, mass-casualty) return `ATTACKER_REFUSED`.
- **Post-processing:** the echo fields are overwritten from the branch. If the LLM errors or refuses, the result is an INFO `AttackResult` and the target is never contacted. Otherwise it runs `target_adapter.execute_attack(payload)` and builds `AttackResult(success=False, score=0, severity=MEDIUM, indicators{objective, expected_failure, expected_safe_behavior, _trace{adversarial_input,target_response,tool_calls_observed}, _observation, _canary})`. The evaluator decides success.
### Strategist → `AttackPlan` (not used by the graph)
```json
{"categories":["..."],"priorities":["..."],"rationale":"..."}
```
### Evaluator → `EvaluationResult` (schema v2)
```json
{"finding_id":"sha256[:16]|null","verdict":"confirmed|unconfirmed|inconclusive|failed",
 "verdict_path":"consensus|deterministic_only|llm_only|heuristic_fallback","score":0.5,"threshold_used":0.5,
 "severity":"info..critical","confidence":"high|medium|low","asi_class":"ASI01..ASI10","asi_class_confidence":"low",
 "atlas_technique":null,"component":"","strategy":"","deterministic_hits":[],"evidence_summary":"","rationale":"",
 "inconclusive_reason":null,"adversarial_input_hash":"","finding_id_inputs":{}, "...deprecated: boundary_failure, finding, evidence, asi_class_suggested, threshold_applied"}
```
### Reporter → `SecurityReport`
```json
{"executive_summary":"","attack_campaign":"","vulnerabilities_found":"","evidence_summary":"","remaining_risks":"","assumptions":""}
```

## Known doc/code discrepancies
- ASI numbering differs between the root README and the foundry README/config.
- The README says 12 strategies; the code has 13.
- `.env.example` is still Bedrock-flavoured.
- The README and code disagree on the `REPORT_FORMAT` default.
- Allowlist fail-open wording differs.
- Advice to bake `VITE_API_TOKEN` into the build vs advice never to do it.
- Thresholds only cover ASI01–06.
- The LICENSE file is missing.
- Stale comments say "up to 3 branches" (the cap is 12).
- `priorities` is ignored and `reference_examples` is never sent.
