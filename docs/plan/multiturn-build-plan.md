# Canary multi-turn platform: build plan

Goal: make Canary a production-grade, **multi-turn** safety-testing product for **any HTTP-based AI agent the operator owns**. It must be safe to point at a real deployment, and its verdicts must be trustworthy.

**Audience:** Opus and Sonnet build agents. Read `part1-notes.md`, `part2-notes.md` and `production-gaps.md` first. Gap IDs (A1, B3, C1…) refer to `production-gaps.md`.

**Repo:** `~/Documents/canary`, base `main` @ 7696621. Backend paths are relative to `cyber-redteam-foundry/src/cyberredteam/`. Frontend paths are relative to `canary/`.

**Scope note:** this plan covers the platform: sessions, conversation plumbing, safety controls, evaluation, data, API, UI and operations. The attacker's per-turn message strategy sits behind the `TurnPlanner` interface (WP4). It is specified and reviewed separately by the security owner, and its content is out of scope for this document.

---

## 0. Ground rules

- **Commits only, no PRs.** All work lands as commits on branch `multiturn`. Never open a pull request, never push to `main`, never force-push.
  - Each work package is one or more small commits, each with its tests, named `WPn: <what>` (e.g. `WP2: SessionAdapter cookie session mode`).
  - Commit after every green step (tests and lint pass). Never leave work uncommitted at the end of a session.
  - Parallel agents each work in their own git worktree on a sub-branch (`multiturn-wp2`, …) and commit there. The lead (Opus) merges them into `multiturn` locally with `git merge --no-ff` after review. No PRs.
- **Checks that must pass:** `uv run pytest -q`, `uv run ruff check .`, and in `canary/` both `npm run build` and `npm run lint`.
- **Review gate (mandatory).** Every WP branch is reviewed by a separate, read-only review subagent before the lead merges it.
  - The reviewer checks: the diff against the plan, the contracts, tests and lint run independently, security (no secrets in logs or bundles, fail-closed behaviour), and dead code left behind.
  - The reviewer returns findings marked must-fix or nice-to-have. The build agent fixes every must-fix in new commits, then the reviewer re-checks.
  - Nothing merges with an open must-fix.
- **Purge subagent.** A dedicated agent deletes old and redundant code on branch `multiturn-purge`.
  - Each deletion needs evidence: a grep showing it has no references, and a test run.
  - It never touches files an active WP owns.
  - It runs once at the start (legacy cleanup), then again after each phase, to remove code that phase replaced (e.g. `HttpTargetAdapter` after WP2, the v1 routes after WP8).
  - Its branch goes through the same review gate.
- **WP0 freezes the contracts in section 2.** Later WPs change them only by editing this file in the same commit.
- **Keep:**
  - FastAPI, LangGraph fan-out, and `ObservableLLM` structured output
  - the finding lifecycle and fail-closed behaviour (never fabricate output)
  - **LLM provider: Backboard.io** (WP0b), replacing NVIDIA NIM. Port `llm/backboard.py` (`ChatBackboard`) from `origin/worktree-backboard-cleanup`; read it, don't merge that branch wholesale.
- **Tests never touch a real LLM or network.**
  - Extend `tests/fixtures/fake_llm.py`.
  - Add `tests/fixtures/fake_target.py`, a stateful in-process HTTP agent with configurable safe and unsafe behaviours.
- **Model assignment:**
  - **Opus** owns design-heavy WPs: WP0, WP1, WP3, WP4 and WP5.
  - **Sonnet** owns mechanical WPs: WP2 and WP6–WP10, plus the test suites.
- **Priority order:** safety controls (WP1–2) ship before any conversation execution (WP3+) reaches a non-fake target.

---

## 1. Target architecture

```
Operator (authenticated user)
  │  registers Target → ownership verified (WP1)
  ▼
Campaign (POST /api/v2/campaigns)  ── policy: budgets, rate limits, allowed techniques
  ▼
Job queue → Worker (WP7)
  ▼
LangGraph run
  strategist (deterministic: techniques × trials)
    → Send(conversation_branch) ×N   (parallelism capped per target)
        loop per conversation (WP3):
          TurnPlanner.next_turn()   ← interface only (WP4)
          SessionAdapter.send()     ← HTTP, stateful, rate-limited (WP2)
          TurnMonitor.check()       ← per-turn detectors, stop conditions (WP5)
        until stop condition / turn budget
    → evaluator (conversation-level verdict, WP5)
    → reporter
  ▼
Postgres (WP6): targets, campaigns, conversations, turns, verdicts, findings, audit_log
  ▼
SSE/UI (WP8–9): live transcript view, findings triage
```

A **conversation** replaces today's single attack. A **turn** is one request–response pair.

---

## 2. Contracts (frozen in WP0)

All are Pydantic v2 models in `contracts.py` (frozen in WP0; the legacy single-turn models stay in `schemas.py`). They are mirrored in `canary/src/lib/contracts.ts`. The code is authoritative for field bounds; this section is the summary.

- Every model forbids unknown fields. ASI classes match `^ASI(0[1-9]|10)$`; `normalize_asi_code()` converts legacy `ASI-01` values.
- `TargetAuth` is a union discriminated on `type`: `none`, `bearer {token}`, `header {header_name, value}`, `oauth_client_credentials {token_url, client_id, client_secret, scope?, audience?}`, `cookie_login {login_url, username, password, username_field, password_field}`. Secret fields are `SecretStr` and serialise masked (`**********`); they never round-trip. Validation **rejects** the literal mask and empty strings as secret values, so a dumped config cannot be reloaded with `**********` as a credential (WP1 adds keep-existing semantics for updates).
- `request_template` must be valid JSON. Every `{{...}}` token must exactly equal one of `{{MESSAGE}}`, `{{SESSION_ID}}`, `{{HISTORY}}` (no inner whitespace; unknown names, including the legacy `{{PROMPT}}`, are rejected). A placeholder may only be a whole quoted JSON string **value**: never a key, never part of a longer string. `"{{MESSAGE}}"` appears exactly once; the other two at most once. Each quoted placeholder is replaced whole by `json.dumps(value)`. `server_session` requires `session_id_path`.
- Production rules (section 4) are **rejected, not clamped**. A bare `CampaignPolicy` cannot see the target's environment and does **not** enforce them. **Campaign creation MUST validate through `CampaignRequest {target: TargetConfig, policy: CampaignPolicy}`**, whose validator always applies the rules. (`CampaignPolicy.model_validate(data, context={"environment": ...})` and `validate_policy_for_target(policy, target)` exist for callers that already hold both halves.) Note the default policy is invalid for production.
- Models not spelled out below: `ToolCallObservation {name, arguments, call_id?, source: "structured"|"heuristic"}` and `JudgeVote {vote_index, judgement: "unsafe"|"safe"|"inconclusive", first_failing_turn?, asi_class?, severity, confidence, rationale, model_name?, temperature=0}`. `temperature` is informational only (Backboard has no temperature parameter).
- `TechniqueResult.from_counts()` computes the Wilson interval.

```python
class TargetConfig(BaseModel):
    target_id: str                      # uuid
    name: str
    endpoint: HttpUrl
    method: Literal["POST"] = "POST"
    auth: TargetAuth                    # none | bearer | header | oauth_client_credentials | cookie_login
    request_template: str | None        # JSON with "{{MESSAGE}}", optional "{{SESSION_ID}}", "{{HISTORY}}"
    response_path: str | None           # dot path to the reply text
    session_mode: Literal["stateless_history", "server_session", "cookie"]
    session_id_path: str | None         # where the target returns its session/thread id
    tool_trace_path: str | None         # optional dot path to structured tool calls in the response
    streaming: Literal["none", "sse", "ndjson"] = "none"
    timeout_s: int = 60
    verified: bool = False              # set only by the ownership check (WP1)
    environment: Literal["staging", "production"]

class CampaignPolicy(BaseModel):
    techniques: list[str]
    trials_per_technique: int = 5       # repeated independent conversations
    max_turns: int = 8
    max_parallel_conversations: int = 4
    rate_limit_rps: float = 1.0         # per target, enforced centrally
    max_total_requests: int = 500
    max_llm_cost_usd: float = 10.0
    stop_on_first_confirmed: bool = False
    allow_destructive_tools: bool = False   # must stay False for environment="production"

class Turn(BaseModel):
    conversation_id: str
    index: int
    role_sent: Literal["user"]
    message: str
    response_text: str
    tool_calls: list[ToolCallObservation]   # structured if tool_trace_path is set, else []
    http_status: int | None
    latency_ms: float
    monitor_hits: list[str]
    error: str | None

class Conversation(BaseModel):
    conversation_id: str
    campaign_id: str
    technique: str
    trial_index: int
    status: Literal["running", "stopped_budget", "stopped_monitor", "stopped_target_refusal_streak",
                    "stopped_target_error_streak", "stopped_killed",   # added in WP3
                    "completed", "cancelled", "error"]
    turns: list[Turn]
    target_session_ref: str | None

class ConversationVerdict(BaseModel):
    conversation_id: str
    verdict: Literal["confirmed", "unconfirmed", "inconclusive", "failed"]
    first_failing_turn: int | None
    deterministic_hits: list[str]
    judge_votes: list[JudgeVote]        # k independent votes, temperature 0
    judge_agreement: float
    severity: Literal["info", "low", "medium", "high", "critical"]
    asi_class: str                      # canonical form "ASI01"…"ASI10" everywhere
    rationale: str

class TechniqueResult(BaseModel):       # aggregate over trials
    technique: str
    trials: int
    confirmed: int
    success_rate: float
    ci95_low: float                     # Wilson interval
    ci95_high: float
```

**SSE events (v2).** Every event is `{"type", "payload", "timestamp", "seq"}`, with a typed payload per type (`parse_sse_event()`); on the wire, `to_sse()` writes `id: <seq>` so clients resume with `Last-Event-ID`. Event text is **truncated, never rejected** (`truncate_preview()`): turn previews to 280 characters; `turn.error`, the `verdict` event's rationale and `campaign_failed.message` to 500. Types:
- `campaign_started`
- `conversation_started`
- `turn` (redacted preview)
- `monitor_hit`
- `conversation_finished`
- `verdict`
- `budget_update`
- `campaign_complete`
- `campaign_failed`
- `campaign_cancelled`

There are no scripted or cosmetic events (fixes D8).

---

## 3. Work packages

### WP0: Contracts and fixtures (Opus)
- Add the section 2 models, `types.ts` mirrors, and the `fake_target.py` fixture.
- `fake_target` behaviour profiles: `always_safe`, `leaks_after_n_turns`, `tool_misuse_on_turn_k`, `flaky_500`, `slow`, `session_server`.
- Normalise ASI codes to `ASI01` across backend, UI and configs (fixes the UI/backend mismatch).
- **Done when:** models validate, fixtures run, and the contract tests pass.

### WP0b: Backboard LLM backend (Sonnet)
- **Port from the cleanup branch:**
  - `ChatBackboard`, a LangChain `BaseChatModel` that calls `POST {BACKBOARD_BASE_URL}/threads/messages` with header `X-API-Key`. Provider and model are chosen per request (`llm_provider`, `model_name`), each call is stateless, and the system prompt is sent on every turn.
  - `BackboardError` and `BackboardRetryableError` (429/5xx).
  - `extract_json` for structured output.
- **Rename** `llm/bedrock.py` → `llm/observable.py` (`ObservableLLM`). Delete the NVIDIA, botocore and langchain-aws remnants and their dependencies.
- **Per-role model config** in `configs/models.yaml`: `{role: {provider, model_name, temperature}}` for each of planner, judge and reporter. The judge always runs at **temperature 0**.
- **Structured output:** Backboard returns text, so `with_structured_output` = prompt + JSON schema in the system message, then `extract_json` + Pydantic validation. Allow **one** repair re-ask on a validation error, then fail closed.
- **Retries:** only on `BackboardRetryableError`, with exponential jitter, honouring `MAX_RETRIES`.
- **Env:** `BACKBOARD_API_KEY` (required, fail closed), `BACKBOARD_BASE_URL`, `BACKBOARD_TIMEOUT_SECONDS`, plus per-role overrides `BACKBOARD_<ROLE>_PROVIDER` / `_MODEL_NAME`. `cyber-rt doctor` pings Backboard.
- **Tests:** a fake Backboard transport (`httpx.MockTransport`), with no network calls.
- **Done when:** every agent role runs through Backboard, the NVIDIA code is gone, and the doctor command plus the tests are green.
- **Status: merged.** Two known deviations:
  - **No temperature control.** Backboard's `POST /threads/messages` has no temperature parameter (https://docs.backboard.io/concepts/messages), so judge temperature 0 is **not enforceable**. Temperature stays in the role config for information only. WP5 must get stable verdicts another way: k ≥ 3 judge votes with majority, judge agreement recorded, and low agreement treated as inconclusive. It must not rely on determinism.
  - **Model IDs unconfirmed.** `anthropic/claude-sonnet-5-5` (evaluator, judge) and `openai/gpt-4o` (other roles) still need confirming with a live `cyber-rt doctor` run against a real `BACKBOARD_API_KEY`. `test_all_roles_configured` hard-codes these IDs, so update it when they change.

### WP1: Target registration and ownership verification (Opus) — C4, C6
- `POST /api/v2/targets` creates an unverified target.
- **Verification:** one of
  - an HTTP well-known file at `/.well-known/canary-verify.txt`, or
  - a DNS TXT record, or
  - a response header the target echoes containing a per-target token.
- Port `security/target.py` and `security/tokens.py` from `feature/cutc-2026-differential-gate`. Read it, don't merge it.
- **Campaigns are refused on unverified targets.** Delete the localhost rewrite in `api.py:916-921` and the optional-allowlist fail-open path.
- Secrets in `TargetAuth` are encrypted at rest (Fernet, key from env), never returned by the API, and never logged.
- **Done when:** a campaign against an unverified target returns 403, and tests cover all three verification methods.
- **WP1 status/deviations (branch `multiturn-wp1`):**
  - `security/` = `crypto.py`, `tokens.py`, `ownership.py` (URL/IP guard ported from the differential-gate `target.py` into it), `targets.py`. `TargetStore` has the six agreed methods **plus** `set_allowed_auth_hosts` / `get_allowed_auth_hosts` (WP2-review addition); the WP6 SQL store must implement all eight.
  - `token_url` / `login_url` must be public http(s) and on **exactly** the endpoint's host, or be listed in `allowed_auth_hosts`. This is stricter than "same registrable domain": without the Public Suffix List, eTLD+1 fails open on shared hosting such as `*.herokuapp.com`. The rule is checked at registration (422) and again at verify. The default A/AAAA resolver (`getaddrinfo`) has no timeout of its own.
  - The IP guard runs at registration/verify time only (DNS-rebinding gap). WP2's `SessionAdapter` must re-run `ownership.check_target_url` / `check_target_urls` before sending.
  - The legacy `/api/runs` and `/api/campaigns/run` now need a verified registered target (`target_id`, or an exact `target_url` match for the old UI), else 403. `ALLOWED_TARGETS` only narrows that further; `REQUIRE_TARGET_ALLOWLIST` is no longer read. The legacy runner still gets the client's headers/template, not the stored auth (left to WP2).
  - `POST /verify` returns 200 with `verified: true|false` and a reason. A failed check is not an HTTP error.
  - Not done (out of scope): `tools/target_adapter.py` still has its own Docker localhost→`host.docker.internal` rewrite. The in-memory store is lost on restart until WP6.

### WP2: SessionAdapter — stateful HTTP client (Sonnet) — A1, D3, D4, C1
- Replace `HttpTargetAdapter` with `SessionAdapter`, using `httpx` with async, a connection pool and HTTP/1.1 + 2.
- **Session modes:**
  - `stateless_history`: the adapter keeps the transcript and renders `{{HISTORY}}` (OpenAI-style messages array).
  - `server_session`: it captures the session id from `session_id_path` and sends it back via `{{SESSION_ID}}`.
  - `cookie`: it keeps a cookie jar per conversation.
- **Auth:** bearer, a custom header, OAuth client-credentials with refresh, and cookie login.
- **Streaming:** SSE and NDJSON responses are assembled into the full reply text.
- **Rate limiting:** a central per-target token bucket shared across workers (Redis or a Postgres advisory lock) that honours `rate_limit_rps`. It backs off on 429/503 using `Retry-After`. Retries happen only on network and 5xx errors, at most 2, and **never re-send a message that already got a 2xx**.
- **Errors are typed results, never reply text.** This fixes D3, where error strings were sent to the judge.
- **Tool observability:** if `tool_trace_path` is set, parse structured tool calls. The regex extraction in `attacker.py:20-36` is kept only as a labelled `heuristic` fallback.
- **Done when:** it works against `fake_target` in all session modes, rate-limit tests pass, and a 2xx response is never retried.
- **WP2 status / deviations:**
  - HTTP/2 is not enabled (no `h2` dependency); the client is pooled HTTP/1.1.
  - The distributed rate limiter is deferred to WP7; `InProcessTokenBucket` implements the `RateLimiter` protocol (`acquire`, `penalize`).
  - Heuristic tool calls carry `source="heuristic"` and must never count as evidence in WP5.
  - WP1 must validate the `endpoint`, `token_url` and `login_url` hosts (SSRF): the adapter does not.
  - Once a status line arrives the request is never re-sent; bodies are capped at 2 MiB and each attempt has an overall `timeout_s` deadline.

### WP3: Conversation engine (Opus) — A1, A2, A3
- New graph node `conversation_branch`. It replaces `attacker_branch` and runs a bounded loop:
  1. `planner.next_turn(state)` → message, or `None` to end.
  2. `adapter.send(...)`.
  3. `monitor.check(turn)` → hits plus a stop signal.
  4. Persist the turn immediately (no end-of-run batching, which fixes the D1 data loss).
  5. Emit an SSE `turn` event.
- **Stop conditions:**
  - `max_turns` reached
  - a monitor stop (for example, a confirmed critical data leak means stop immediately and do not continue the conversation)
  - campaign budget exhausted
  - a cancel flag
  - a target error streak of 3 or more
- **Strategist:** produces `techniques × trials_per_technique` branches. Parallelism is capped by `max_parallel_conversations` through a semaphore, not by truncating the list.
- **Budget accounting:** a central `BudgetLedger` (requests, LLM tokens converted to estimated USD) is checked before every turn. When exhausted, conversations end with `stopped_budget`.
- **Done when:** fake runs produce full transcripts, budgets and cancel stop runs mid-conversation, and every turn is in the DB as it happens.
- **Phase 3 seams (frozen by the lead before Phase 3 starts, so WP3, WP7 and WP11 can build in parallel):**
  - `engine/control.py`: the `RunControl.check(campaign_id) -> "cancelled" | "killed" | None` protocol, plus `InMemoryRunControl`. WP3 calls it before every turn. WP7 supplies the durable Postgres implementation and the kill switch. On a read error it fails closed (`"killed"`).
  - `observability/hooks.py`: `trace_op(name)` decorator and `get_metrics()` → `CampaignMetrics` (`campaign_started`, `log`, `campaign_finished`, `alert`). The defaults are no-ops. WP3 and WP7 call them; WP11 installs the Weave and wandb implementations via `set_tracer` and `set_metrics`. These hooks never raise into the caller.
  - Planner and monitor are injected into WP3 as protocols. Tests use a fake scripted planner with benign messages. Real planners are WP4; real detectors and the judge are WP5.
- **WP3 status / deviations (branch `multiturn-wp3`):**
  - **Code layout.** `engine/types.py` holds the protocols and models, `engine/monitors.py` the `BuiltinSafetyMonitor`, `engine/budget.py` the `BudgetLedger`, and `engine/runner.py` `run_conversation`, `run_campaign` and `EngineDeps`. `langgraph/campaign_graph.py` holds the v2 graph.
  - **New statuses (contract change).** `ConversationStatus` gains `stopped_killed` (kill switch) and `stopped_target_error_streak` (3+ target errors in a row), plus a `TERMINAL_CONVERSATION_STATUSES` set. Cancel maps to the existing `cancelled`. `max_turns`, or the planner returning `None`, gives `completed`. Any monitor stop gives `stopped_monitor`. A planner or engine exception gives `error`.
  - **Safety inputs not in `TargetConfig`.** The canary values, the forbidden/destructive tool names and the on-call notifier are `EngineDeps` fields (`canary_values`, `forbidden_tools`, `on_call`), supplied by WP7/WP8. Open question: should the target record carry them?
  - **`PlannedTurn` additions.**
    - Optional `llm_tokens` and `llm_cost_usd` fields let a planner report its spend to the `BudgetLedger`.
    - `end_conversation=true` ends the conversation **without sending** that message.
  - **`MonitorResult.hits`** is a list of `MonitorHit {name, severity}`, not plain strings; the names go into `Turn.monitor_hits`. `TurnPlanner.next_turn` and `TurnMonitor.check` are async.
  - **Heuristic tool calls** (`source="heuristic"`) on the forbidden list produce a non-critical `forbidden_tool_heuristic` hit and never stop the conversation. Only structured calls are critical.
  - **Fail-closed behaviour.**
    - A monitor exception records `monitor_error:<Class>`, keeps the turn, and stops with `stopped_monitor`.
    - A `RunControl.check` exception is treated as `"killed"`.
    - Event-sink, metrics and on-call failures are swallowed and logged.
  - **Budget.**
    - Requests count actual HTTP attempts, so SessionAdapter retries are charged. One slot is reserved before each turn, so parallel conversations cannot all pass the last-request check. Retries of in-flight turns can still overshoot the cap by at most 2 requests each.
    - A cost-free planner is never stopped by `max_llm_cost_usd` (even 0).
    - Totals reload from `budget_ledger` on a re-run.
  - **Resume.**
    - Conversation ids are `uuid5(campaign_id, technique, trial_index)`. Re-running skips terminal conversations.
    - A `running` conversation resumes from its persisted turns. This reads the raw transcript (audited `evidence.read_raw` with actor `system:engine-resume`), because the redacted preview is truncated.
    - New `SessionAdapter.restore(history, session_id)` reseeds `{{HISTORY}}` and the server session id, which is persisted to `target_session_ref` as soon as it is captured.
    - Cookie jars cannot be restored: a resumed cookie-mode conversation starts a new target session.
    - A turn sent but not yet persisted when the worker died is re-planned.
    - Task cancellation leaves the conversation `running`. Campaign status is `running`, then `completed`, or `cancelled` (cancel or kill), or `failed`.
  - **`X-Canary-Campaign`** was already set by `SessionAdapter` on every request, including auth sub-requests. WP3 adds an engine-level test.
  - **LangGraph.** `run_campaign` is the primary entry point. `build_campaign_graph()` / `run_campaign_graph()` (strategist → `Send(conversation_branch)`×N → collect) is a thin adapter that shares `run_conversation` and the semaphore through `config["configurable"]`. It runs without a LangGraph checkpointer, because resume comes from the DB. The legacy v1 `build_redteam_graph` is unchanged.
  - **Not done.**
    - `stop_on_first_confirmed` needs WP5 verdicts.
    - `campaign_complete.confirmed` is always 0 until WP5.
    - Repository calls are synchronous on the event loop (short single transactions).
    - `trace_op` resolves at decoration (import) time, so WP11 must call `set_tracer` before `cyberredteam.engine` is imported.

### WP4: TurnPlanner interface (Opus, interface only)
- Define a `TurnPlanner` protocol with `next_turn(conversation_state) -> PlannedTurn | None`. Inputs are the technique spec, the transcript so far, the monitor hits, and the remaining turns.
- Ship two implementations:
  1. `ScriptedPlanner`, which replays operator-supplied turn scripts from YAML in `packs/`. Deterministic, used for regression suites.
  2. `LLMPlanner`, which wraps the existing structured-output chain with a new `PlannedTurn` schema `{message, intent_note, end_conversation: bool}`. Its system prompt is **owned and reviewed by the security owner** and lives in `prompts/planner.md` (out of scope here).
- **Planner guard rails, enforced in code:**
  - a refusal from the planner model ends the conversation, logged as `planner_refused` and never counted as safe
  - a per-message length cap
  - no content outside the campaign's technique scope (classifier check)
  - the hard-refusal categories from today's `attacker.md` are kept
- **Done when:** both planners plug into WP3, and `ScriptedPlanner` runs a full campaign deterministically.

### WP5: Trustworthy evaluation (Opus) — B1–B9
- **Per-turn monitors**, deterministic and configured per target:
  - secret patterns plus **operator-registered canary values** (strings planted in the target's own test data, recorded on the target)
  - PII detectors (use `presidio-analyzer` instead of the hand regexes)
  - **forbidden tool list** checks against structured tool calls
- Delete the demo-specific strings (`pr0d_s3cr3t`, `sk-internal`, names, `employee_lookup`) from the code. Move them into the demo target's config.
- **Judge:**
  - temperature 0, k=3 independent votes (configurable)
  - judges the **raw** transcript (remove the sanitizer, fixing B5) inside clear data delimiters, using a structured `JudgeVote` schema
  - verdict decided by majority plus the deterministic consensus table (keep today's table; fix the prompt so it matches the code, B6)
  - record `judge_agreement`; low agreement means `inconclusive`
- **Conversation-level verdict** includes `first_failing_turn`.
- **Aggregation:** `TechniqueResult` with Wilson CI over trials (B8). Reports show rates, not single pass/fail results.
- **Findings:** the ID includes the real component (fixes `component=""`, B7). Semantic dedup actually merges duplicates above the threshold, with a human override. **Inconclusive verdicts open a `needs_review` finding** (B9).
- **Calibration harness** `eval/calibrate.py`: runs the judge on a labelled set of transcripts (start with 200, half safe and half unsafe, built from `fake_target` plus hand-labelled samples) and reports precision, recall and Cohen's kappa against the labels. **A judge or prompt change must not drop precision or recall by more than 2 points** (enforced in CI).
- **Done when:** the calibration report is generated in CI, and the demo strings are gone from `src/`.

### WP6: Data layer (Sonnet) — D1, D2, C7
- Postgres with SQLAlchemy 2 + Alembic. SQLite remains for local dev only.
- **Tables:**
  - targets, target_secrets (encrypted)
  - campaigns, conversations, turns
  - judge_votes, verdicts, technique_results
  - findings, finding_events (lifecycle, with **reviewer_id and rationale stored**)
  - audit_log, budget_ledger
  - All with foreign keys and indexes.
- **Evidence protection:**
  - `turns.message` and `turns.response_text` are encrypted at rest.
  - A redaction pass masks detected PII and secrets in anything shown in the UI and logs. Raw text is viewable only with an `evidence:read_raw` permission and is audited.
  - Retention: configurable per target (default 30 days), with a purge job.
- **Embeddings:** pgvector for finding dedup.
- **Done when:** migrations run up and down, the retention purge is tested, and raw evidence is never logged.
- **WP6 status / deviations:**
  - Implemented in `storage/v2/` with Alembic revision `0001` (SQLite and Postgres/pgvector).
  - The Dockerfile does not ship `alembic.ini` or `migrations/`; WP7 adds `alembic upgrade head` to startup.
  - The `evidence:read_raw` permission is enforced in WP8. The repos only require an `actor` for `raw=True` reads and write an `evidence.read_raw` audit row.
  - `CampaignRepo.create` does not validate the policy against the target environment; it must only be reached through `CampaignRequest` validation.
  - Fernet crypto in `storage/v2/encrypted.py` duplicates WP1's `security/crypto.py` (same key semantics); the purge agent dedupes later.
  - `SqlTargetStore.create` always stores `verified=False`; the retention purge keeps encrypted verdict rationales and wipes raw turn text, raw tool calls and session refs.

### WP7: Jobs, workers, control plane (Sonnet) — C1, D1
- A queue (Postgres-backed with `procrastinate`, or Redis + `arq`). API process and worker processes are separate.
- **Runs are resumable:** a worker restart continues from the last persisted turn using the LangGraph checkpointer (PostgresSaver).
- **Cancel:** `POST /api/v2/campaigns/{id}/cancel` sets a flag checked before every turn. A **global kill switch** (env var or admin endpoint) halts all campaigns within one turn.
- An SSE disconnect never affects the run; the client can reconnect with `Last-Event-ID` (`seq`).
- **Done when:** a kill-switch test stops 10 parallel fake conversations within one turn each, and a resume test passes.

### WP8: API v2 and auth (Sonnet) — C5, C6
- **Users:** OIDC login (GitHub/Google), or API keys for CI. Roles are `viewer`, `operator` and `admin`.
  - Only an operator may launch a campaign, and only against targets in their org.
  - **No token ever appears in a `VITE_*` variable.**
  - The Vercel proxy forwards the user's session; it does not inject a master token.
  - Constant-time key comparison.
- **Endpoints:**
  - `/api/v2/targets` (CRUD, verify)
  - `/api/v2/campaigns` (create, list, get, cancel, events SSE)
  - `/api/v2/conversations/{id}` (transcript, redacted by default)
  - `/api/v2/findings` (paged with total; lifecycle transitions with stored reviewer)
  - `/api/v2/reports/{campaign_id}` (JSON, Markdown and PDF)
  - `/api/v2/admin/kill-switch`
- Keep v1 read routes behind a deprecation flag for one release. Remove `POST /api/runs` and the old SSE route.
- **Done when:** auth tests cover every role and route, and no secret appears in the built JS (CI greps the bundle).

### WP9: Frontend (Sonnet) — D8
- **Target onboarding wizard:**
  - endpoint, auth, session mode, template and response path
  - a **"test connection"** button that sends one benign hello and shows the parsed reply
  - verification instructions
- **Campaign builder:** techniques, trials, turns, budgets. Production targets are forced to safe defaults.
- **Live view:**
  - a conversation grid (technique × trial) with a status per cell
  - clicking a cell opens the **chat transcript** turn by turn, with monitor hits highlighted
  - a budget meter and Cancel button; the kill switch for admins
- **Results:** a per-technique success-rate table with CI bars; findings triage linking to the exact failing turn.
- Fix the existing bugs: null `score` crash, findings pagination with total, ASI filter debounce, handling every SSE event type.
- **Done when:** the build and lint pass, and a Playwright smoke test runs a fake campaign end to end.

### WP10: CI gate and regression suites (Sonnet) — D5
- A CLI command plus a GitHub Action, `canary gate --target <id> --suite <pack> --baseline <campaign_id>`. It fails the build when a technique's success-rate CI lower bound rises above the baseline's upper bound.
- Salvage the differential logic from `feature/cutc-2026-differential-gate`: read `evaluation/differential.py` and `release_policy.py` and port them to the v2 schemas.
- ScriptedPlanner packs act as fixed regression suites; LLMPlanner runs act as exploratory suites.
- **Done when:** the action runs against `fake_target` in CI and fails on an injected regression.

### WP11: Production observability and telemetry on Weights & Biases (Sonnet; Opus reviews the redaction)
Two layers: **W&B Weave** for traces and LLM calls, and **W&B Runs (`wandb`)** for campaign metrics. Add both as optional dependencies: `weave`, `wandb`.

**1. Tracing with Weave** (`observability/weave_tracing.py`)
- At startup, `weave.init(f"{WANDB_ENTITY}/{WANDB_PROJECT}")` in both the API and the workers. This is a no-op when `WANDB_API_KEY` is unset, and nothing fails if W&B is down.
- Decorate with `@weave.op`: `ChatBackboard._generate`, `TurnPlanner.next_turn`, `SessionAdapter.send`, `TurnMonitor.check`, judge votes, the conversation verdict and the reporter.
  - The trace tree is campaign → conversation → turn → (planner LLM call, target HTTP call, monitors, judge votes).
  - Attach the attributes `campaign_id`, `conversation_id`, `turn_index`, `target_id`, `technique`, `environment`, `role`, `provider`, `model_name`, `tokens_in`/`tokens_out`, `latency_ms`, `est_cost_usd`, `http_status` and `verdict`.
- **Redaction before export:** a `postprocess_inputs`/`postprocess_output` hook runs the WP6 PII and secret redactor. Target auth headers and secrets are never exported. Raw evidence text is exported **only** when `WANDB_EXPORT_RAW_EVIDENCE=true` and the target is `staging`; production gets hashes plus redacted previews.
- Judge votes are logged as Weave feedback on the turn and conversation calls. Human triage decisions (finding lifecycle changes with reviewer) are pushed as feedback too, so judge-vs-human agreement can be tracked.
- **Evaluations:** the WP5 calibration harness runs as a `weave.Evaluation` over a versioned `weave.Dataset` of labelled transcripts, with precision, recall and kappa as scorers. Each judge-prompt or model change is a new evaluation, compared in the Weave UI.
- Prompts (`prompts/*.md`) are published as `weave.StringPrompt` objects so every trace records the prompt version used.

**2. Campaign metrics with W&B Runs** (`observability/wandb_metrics.py`)
- One `wandb.init(project=WANDB_PROJECT, job_type="campaign", id=campaign_id, resume="allow", config=CampaignPolicy + target metadata minus secrets)` per campaign, owned by the worker that runs it. Resume support covers WP7 worker restarts.
- **Live metrics**, logged with `step` = turns completed:
  - `turns_total`, `requests_total`, `target_latency_ms` (histogram), `target_error_rate`, `rate_limit_backoffs`
  - `llm_tokens{role}`, `llm_cost_usd`, `budget_remaining_pct`
  - `conversations_{running,completed,stopped_*}`, `monitor_hits{type}`
- **At the end:**
  - a `wandb.Table` of `TechniqueResult` (success_rate, CI low and high)
  - a verdict summary bar chart and a redacted findings table
  - the JSON and Markdown report logged as an **Artifact** (`report-<campaign_id>`) that links back to the Weave traces
  - `run.summary` holds the headline numbers, so the W&B project table compares campaigns over time
- **CI gate (WP10):** each gate run logs `job_type="gate"` with the baseline id, so regressions show up in W&B charts.

**3. Ops telemetry (service health)**
- A background reporter in the API and workers logs, every 60 s, to a long-lived `job_type="service"` run per process: queue depth, active campaigns, worker heartbeat, kill-switch state and Backboard error rate.
- Keep structured JSON logs (`log_event`) to stdout as the source of truth. W&B is for observability, not the audit log, which stays in Postgres (WP6).
- **Alerts:** use `wandb.alert(...)` for a critical finding in a production target, a kill-switch activation, a budget overrun, a Backboard error rate above 20% over 5 min, and a target error streak. Also send the same alert to the target's on-call webhook.

**Config:** `WANDB_API_KEY`, `WANDB_ENTITY`, `WANDB_PROJECT=canary`, `WANDB_MODE` (`online`, `offline` or `disabled`; tests force `disabled`), `WANDB_EXPORT_RAW_EVIDENCE=false`.

**Done when:**
- A fake campaign with `WANDB_MODE=offline` produces a run containing the metrics, tables and report artifact.
- The Weave trace tree exists for campaign → conversation → turn → calls.
- A redaction test proves no secret or raw PII leaves the process.
- The calibration evaluation appears in Weave.
- With W&B unreachable, campaigns still complete.

---

## 4. Production-safety defaults (non-negotiable)

These apply whenever `environment == "production"`:
- `rate_limit_rps` ≤ 1 and `max_parallel_conversations` ≤ 2
- `max_total_requests` ≤ 300
- `allow_destructive_tools=false`
- **No resource-exhaustion techniques.** The workflow_manipulation/DoS technique is staging-only.
- **Conversation halted** immediately on a critical monitor hit (real data exposure). The target's on-call contact is notified (webhook on the target record).
- **Every request carries `X-Canary-Campaign: <id>`** so the target owner can identify and filter test traffic.
- The kill switch is tested in CI.

---

## 5. Sequencing

| Phase | WPs | Parallel? | Exit criterion |
|---|---|---|---|
| 1 | WP0, WP0b | yes | contracts merged; all LLM calls via Backboard |
| 2 | WP1, WP2, WP6 | yes (3 agents) | verified target + SessionAdapter + Postgres |
| 3 | WP3, WP7, WP11 | yes | conversations persist turn by turn, cancel works, Weave traces and W&B campaign runs live |
| 4 | WP4, WP5 | yes | ScriptedPlanner campaign with calibrated verdicts |
| 5 | WP8, WP9 | yes | authenticated UI end to end |
| 6 | WP10 | — | CI gate green |

Each phase ends with a review by the lead (Opus): read the diffs, run the full test suite, and update this file if a contract changed.

## 6. Out of scope here

- The content of `prompts/planner.md` and the attacker's turn strategies (owned by the security owner).
- Non-HTTP targets (WebSocket, MCP). Add them later as new `SessionAdapter` transports.
