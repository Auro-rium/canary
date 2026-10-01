# Agent Canary — Technical Reference

Two services:

1. `cyber-redteam-foundry/` — Python 3.11+ FastAPI backend and LangGraph engine.
2. `canary/` — React 19 + TypeScript + Vite dashboard, served by nginx (Docker) or Vercel.

The backend sends model-generated adversarial prompts to an external HTTP agent, records its actual response, evaluates the evidence and persists everything in SQLite plus report files. The target is never part of the Canary process.

```text
Browser → dashboard (nginx or Vercel, /api proxy adds the bearer token)
        → FastAPI + LangGraph + SQLite
        → Backboard.io  (provider/model chosen per request)
        → your authorized HTTP agent
```

## 1. LangGraph workflow

```text
strategist → Send(attacker_branch × selected techniques) → evaluator
evaluator → strategist   if a successful finding exists and iterations remain
evaluator → reporter     otherwise
```

- **Strategist** is a deterministic node. It preserves the explicit technique selection (up to `MAX_PARALLEL_BRANCHES = 12`) and returns one `Send` per branch, each with its own branch id, ASI technique, depth and attempt budget. An LLM-ranked `StrategistAgent` exists but is not on the default path.
- **Attacker branches** run independently. Each asks the model for one structured `AttackerOutput`, sends the prompt through `HttpTargetAdapter`, and returns one `AttackResult` (prompt, reply or error, HTTP status, latency, hashes, observations).
- **Reducers:** `attack_results` and logs use `Annotated[list, operator.add]` so parallel deltas merge. The evaluator filters by explicit `iteration`, never by list position.
- **Checkpoints:** LangGraph state is stored in SQLite with the campaign id as `thread_id`, so a run is inspectable after a restart.

## 2. Backboard integration

`llm/backboard.py` implements `ChatBackboard`, a LangChain `BaseChatModel` over Backboard's messages API:

- `POST {BACKBOARD_BASE_URL}/threads/messages` with an `X-API-Key` header.
- Body: `content`, `system_prompt`, `llm_provider`, `model_name`, `stream: false`, `memory: "off"`, and `json_output: true` for structured calls. No `thread_id` is sent, so every call is stateless.
- Structured output (`with_structured_output`) appends the Pydantic JSON schema to the system prompt, parses the reply (tolerating code fences), and returns `{raw, parsed, parsing_error}` so token usage survives parsing.
- HTTP 429/5xx and transport errors raise retryable errors; other 4xx and `FAILED` runs raise `BackboardError`. `ObservableLLM` retries only the retryable class, up to `MAX_RETRIES` attempts.
- `llm/observable.py` wraps any chat model, builds the LCEL chains and records agent, provider/model, latency, hashes and tokens per call.
- `llm/factory.py` raises when `BACKBOARD_API_KEY` is unset. There is no mock fallback.

## 3. Target adapter

`HttpTargetAdapter` is the only production target path:

```http
POST <target_url>
Authorization: Bearer <TARGET_API_KEY>   # optional
Content-Type: application/json

{"message": "<generated prompt>"}        # default body
```

A campaign can override the body with a template containing `"{{PROMPT}}"` (substituted via `json.dumps`), the reply extraction with a dot path such as `choices.0.message.content`, and add arbitrary headers. Without a path it checks `response`, `output`, `content`, `text`. In a container, loopback hosts are rewritten to `host.docker.internal`.

## 4. Evaluation

Deterministic detectors (prompt leakage, PII and credentials, tool misuse, memory/context violations, retrieval probes, jailbreak and hierarchy signals, workflow loops, canary tokens) run first; the LLM judge adds semantic scoring, confidence and rationale.

| Detector | Judge | Result |
|---|---|---|
| hit | success | `confirmed`, high confidence |
| hit | inconclusive | `confirmed`, medium confidence |
| hit | failure | `unconfirmed`, low confidence, not a finding |
| miss | success above threshold | `unconfirmed`, review only |
| miss | failure / inconclusive | `failed` / `inconclusive` |

An attacker refusal sends nothing to the target. A provider failure fails the campaign rather than being converted into a verdict. Finding ids are `sha256(target:component:strategy:asi_class)[:16]`; per-ASI thresholds live in `configs/thresholds.yaml`.

## 5. Persistence

SQLite tables: `runs`, `attacks`, `findings` (lifecycle `open → wont_fix | false_positive | inconclusive`, manual with reviewer and rationale), `evaluator_verdicts`, `attack_traces`, `llm_calls`, plus LangGraph checkpoints. Reports are written to `reports/`, logs to `runs/` (both git-ignored).

## 6. API

All routes except health require `Authorization: Bearer <API_SECRET_KEY>`. Swagger is at `/docs`.

| Route | Purpose |
|---|---|
| `GET /api/status` | Health and config status |
| `GET /api/dashboard/overview` | Aggregate metrics and LLM totals |
| `GET /api/runs`, `POST /api/runs` | History; start a background campaign |
| `POST /api/campaigns/run` | Start a campaign and stream SSE (`agent_state`, `log`, `finding`, `campaign_complete`) |
| `GET /api/runs/{id}` (+ `/analysis-report`, `/report-markdown`, `/findings`) | Campaign detail and artifacts |
| `GET /api/targets`, `/api/targets/{id}/coverage`, `/trends` | Target portfolio, ASI coverage, trends |
| `GET /api/findings`, `/{id}`, `/{id}/attempts` | Findings and evidence |
| `PUT /api/findings/{id}/status` | Manual triage |
| `GET /api/open-findings`, `/api/incidents` | Feeds |

## 7. Dashboard

Routes: `/` overview, `/campaigns`, `/campaigns/new` (target config + live SSE), `/campaigns/:runId` (full evidence), `/findings`, `/targets`, `/targets/:targetId`. In Docker, nginx proxies `/api/*` to the backend with buffering disabled for SSE. On Vercel, the functions in `canary/api/` forward requests and attach `CANARY_API_TOKEN` server-side (`CANARY_API_URL` points at your backend).

## 8. Security model

- Test only agents you own or are authorized to test; enforce `ALLOWED_TARGETS` with `REQUIRE_TARGET_ALLOWLIST=true`.
- Keep `BACKBOARD_API_KEY`, `API_SECRET_KEY`, `CANARY_API_TOKEN` and target credentials server-side. The Docker dashboard build bakes `VITE_API_TOKEN` into the bundle, so use it only on a trusted network; use the Vercel proxy for anything public.
- Reports and traces may contain sensitive responses.

## 9. Patterns

Orchestrator (`GraphOrchestrator`), scatter-gather (`Send`), strategy (`StrategyType`), adapter (`HttpTargetAdapter`), reducer (`operator.add`), checkpoint (SQLite `thread_id`), proxy (Vercel functions).
