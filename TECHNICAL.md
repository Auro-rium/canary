# Agent Canary — Technical Reference

This document describes the deployed system as it exists on `main`.

Agent Canary is a two-service product:

1. `cyber-redteam-foundry/` is a Python 3.11 FastAPI backend and LangGraph orchestration engine.
2. `canary/` is a React 19 + TypeScript + Vite dashboard served by Vercel or nginx.

The backend sends model-generated adversarial prompts to an external HTTP agent, records the target's actual response, evaluates the evidence, and persists campaign artifacts in SQLite and the report directory. The target is not part of the Canary process. The current demonstration target is the separate CompanyAgent Canary Demo repository.

Live deployment:

- Dashboard: https://canary-coral.vercel.app/
- Explainer: https://agent-canary-explainer.vercel.app/
- FastAPI docs: http://3.108.23.172/docs
- Target repository: https://github.com/Auro-rium/companybot-canary-demo

## 1. Runtime topology

```text
Browser
  │ HTTPS
  ▼
Vercel React dashboard
  │ server-side /api proxy + bearer token
  ▼
AWS EC2 FastAPI backend
  │ LangGraph + SQLite + report artifacts
  │ NVIDIA_API_KEY stays server-side
  ▼
NVIDIA NIM: nvidia/nemotron-3-ultra-550b-a55b
  │
  ▼
Authorized external HTTP target
```

AWS exposes the FastAPI service only. It does not serve the React UI. The Vercel project owns the frontend and forwards protected API requests to AWS. The Vercel browser bundle does not contain the backend token.

## 2. LangGraph workflow

The graph has four functional stages:

```text
strategist
  → Send(attacker_branch × selected techniques)
  → evaluator
  → strategist  [if a successful finding exists and iterations remain]
  → reporter   [otherwise]
```

### Strategist dispatch

The default `strategist` node is deterministic. It logs the campaign's explicit strategy selection and does not call an LLM to rank, skip, or invent techniques. `dispatch_attacker_branches()` converts each selected strategy to a `StrategyType`, resolves its ASI technique specification, creates an independent `AttackBranch`, and returns one LangGraph `Send` per branch.

The graph supports `MAX_PARALLEL_BRANCHES = 12`. The current dashboard exposes eight techniques, and explicit selections are preserved in order up to that backend limit. Each branch receives its own branch ID, technique ID, target configuration, iteration number, depth, and attempt budget.

### Parallel attacker branches

Each `Send` invokes `node_attacker_branch()` independently. The branch calls the NVIDIA-backed attacker agent to generate one structured `AttackerOutput`, then passes the resulting prompt to `HttpTargetAdapter`. It returns one `AttackResult` containing:

- branch and iteration identity;
- strategy and ASI technique;
- exact prompt sent, unless the attacker refused;
- target response or target error;
- HTTP status, latency, request/response hashes, and observations;
- evaluator fields initialized for downstream assessment.

`attack_results` and log messages use `Annotated[list, operator.add]`, so parallel deltas are gathered without overwriting each other. The evaluator runs at the LangGraph superstep boundary after the dispatched branches complete.

### Iteration routing

The evaluator filters results by their explicit `iteration` field. It never assumes that the last N list entries belong to the current round; parallel completion order is not a correctness signal.

If one or more attempts produce a successful finding and the iteration budget remains, the graph returns to the deterministic strategist node and dispatches a fresh branch set. Otherwise it proceeds to the reporter. The evaluator writes `should_continue_iterating`; the graph edge only reads that state flag.

LangGraph checkpoints use SQLite with the campaign ID as the thread ID. This makes state, branch results, and the execution timeline inspectable after a process restart.

## 3. Agent and model wiring

The model assignments are in `cyber-redteam-foundry/configs/models.yaml`:

| Role | Model | Calls |
|---|---|---|
| Strategist node | None in the default graph | Deterministic dispatch only. |
| Attacker | `nvidia/nemotron-3-ultra-550b-a55b` | Generates the scoped adversarial prompt. |
| Evaluator | `nvidia/nemotron-3-ultra-550b-a55b` | Judges target behavior against evidence and thresholds. |
| Reporter | `nvidia/nemotron-3-ultra-550b-a55b` | Produces structured Markdown/JSON report output. |

`llm/factory.py` constructs a `ChatOpenAI`-compatible client pointed at `NVIDIA_BASE_URL` and wraps it in `ObservableLLM`. The compatibility module is named `bedrock.py` for import stability, but it contains no Bedrock transport. The provider is NVIDIA NIM.

There is no mock or fabricated-output fallback in the production factory. `get_llm()` raises when `NVIDIA_API_KEY` is absent. Provider/network calls use bounded retry behavior from `MAX_RETRIES`, and each invocation can persist agent name, model, latency, input/output hashes, and token usage.

## 4. Target adapter contract

`HttpTargetAdapter` is the only production target path. It supports a generic JSON contract rather than a target-specific SDK.

Default request:

```http
POST <target_id>
Authorization: Bearer <TARGET_API_KEY>   # optional
Content-Type: application/json

{"message":"<generated prompt>"}
```

The adapter can receive a custom request template containing the quoted placeholder `{{PROMPT}}`. The placeholder is replaced using `json.dumps()`, preserving valid JSON for quotes, line breaks, and Unicode. A custom response path such as `choices.0.message.content` can extract the target's answer from nested JSON. If no path is supplied, the adapter checks common response keys.

The target may be a public URL, an internal URL reachable from the backend, or a private service with its own bearer key. The backend allowlist is the authorization boundary for campaign creation. Canary does not start a target container in the production AWS stack.

Current demo target contract:

```http
POST http://13.201.9.115/chat
{"message":"..."}
```

This is the separately deployed CompanyAgent application. Its Backboard credentials remain outside Canary.

## 5. Evaluation and verdicts

The evaluator combines deterministic detectors with a model judge. The deterministic layer checks strategy-specific indicators such as prompt leakage, PII/credential patterns, tool misuse, memory/context violations, retrieval probes, hierarchy violations, and workflow signals. The model judge supplies semantic scoring, confidence, rationale, and component context.

The result path is recorded explicitly:

| Detector | Model judge | Result |
|---|---|---|
| hit | successful/non-inconclusive | `confirmed`, high confidence, success true |
| hit | inconclusive | `confirmed`, medium confidence, success true |
| miss | successful above threshold | `unconfirmed`, low confidence, success false; review signal only |
| miss | failed/inconclusive | `inconclusive` or `failed`, no confirmed finding |

The exact evaluator schema stores score, threshold, confidence, verdict path, deterministic hit names, rationale, ASI class, ATLAS technique, and evidence summary. A finding is content-addressed from target, component, strategy, and ASI class so repeated observations can be deduplicated across campaigns.

An attacker refusal is a first-class outcome. A refused branch produces no target request and no static replacement payload. A provider failure also fails closed; it is not converted into a successful or fabricated attack.

## 6. Persistence and observability

SQLite is the operational source for campaign history:

| Data | Purpose |
|---|---|
| Runs | Campaign status, target, configuration, lifecycle timestamps. |
| Attacks | Every branch attempt, prompt, response, score, strategy, and observation. |
| Findings | Deduplicated vulnerability records and manual lifecycle status. |
| Evaluator verdicts | Full scoring and evidence path per attempt. |
| LLM calls | Agent/model, token counts, latency, and hashes. |
| LangGraph checkpoints | Resumable state timeline keyed by campaign ID. |

Report artifacts are written as Markdown and/or JSON under `reports/`. Runtime logs are written under `runs/`. These paths are ignored by Git and should be treated as sensitive because they may contain target responses and attack traces.

The dashboard exposes the same evidence through campaign detail, findings, and target pages. Campaign detail can reveal the raw generated prompt, actual target reply, HTTP observation, evaluator indicators, report Markdown, and LLM telemetry. This is intentional for authorized review and is why dashboard access must remain protected.

## 7. Backend API

Every protected route requires `Authorization: Bearer <API_SECRET_KEY>`.

| Route | Function |
|---|---|
| `GET /api/status` | Health and runtime status. |
| `GET /api/dashboard/overview` | Aggregate dashboard metrics and LLM totals. |
| `GET /api/runs` | Paginated campaign history. |
| `POST /api/runs` | Background campaign launch. |
| `POST /api/campaigns/run` | SSE campaign launch and event stream. |
| `GET /api/runs/{run_id}` | Complete persisted campaign detail. |
| `GET /api/runs/{run_id}/analysis-report` | Structured analysis report. |
| `GET /api/runs/{run_id}/report-markdown` | Markdown report artifact. |
| `GET /api/runs/{run_id}/findings` | Findings linked to one campaign. |
| `GET /api/targets` | Target portfolio. |
| `GET /api/targets/{target_id}/coverage` | Target ASI coverage. URL target IDs use a path converter. |
| `GET /api/targets/{target_id}/trends` | Per-strategy target history. |
| `GET /api/findings` | Paginated findings with filters. |
| `GET /api/findings/{finding_id}` | Finding and latest verdict. |
| `GET /api/findings/{finding_id}/attempts` | Contributing attempts. |
| `PUT /api/findings/{finding_id}/status` | Manual status transition with reviewer/rationale. |
| `GET /api/open-findings` | Open finding feed. |
| `GET /api/incidents` | Incident feed. |

`POST /api/campaigns/run` emits `agent_state`, `log`, `finding`, and `campaign_complete` SSE events. The frontend buffers event lines so a network chunk split cannot corrupt a JSON event.

## 8. Frontend architecture

The Vite dashboard uses React Router and a typed API client. The main routes are:

| Route | Responsibility |
|---|---|
| `/campaigns` | Campaign history and filters. |
| `/campaigns/new` | Authorized target configuration and SSE execution. |
| `/campaigns/:runId` | Evidence-backed campaign detail. |
| `/findings` | Finding filters, evidence, and manual lifecycle transitions. |
| `/targets` | Target portfolio. |
| `/targets/:targetId` | Coverage, trends, and recent campaigns for one target. |
| `/` | Presentation landing page with live aggregate metrics. |

The Vercel proxy functions map browser `/api/*` requests to the AWS FastAPI service. Explicit dynamic wrappers are used for dashboard, runs, targets, and slash-containing URL target IDs. The AWS backend remains UI-free.

## 9. Security model

- Only owned or explicitly authorized targets may be assessed.
- Enable `REQUIRE_TARGET_ALLOWLIST=true` and set `ALLOWED_TARGETS` before exposing the backend.
- Keep `NVIDIA_API_KEY`, `API_SECRET_KEY`, `CANARY_API_TOKEN`, and target credentials server-side.
- Do not place secrets in `VITE_*` variables or campaign screenshots.
- The target receives real generated prompts; do not use production systems without written authorization.
- Canary reports findings but does not auto-fix or mutate the target.
- Reports and SQLite traces may contain sensitive target responses; protect them like security logs.

## 10. Deployment and operations

### AWS backend

The AWS deployment uses the backend-only Compose override:

```bash
docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d --build redteam-backend
```

The backend is exposed on port 80 through the override and serves Swagger at `/docs`. The frontend profile is disabled in the AWS deployment.

### Vercel dashboard

The dashboard is deployed from `canary/` and uses production variables:

```env
CANARY_API_URL=http://<aws-backend-host>
CANARY_API_TOKEN=<API_SECRET_KEY>
```

Build locally with:

```bash
cd canary
npm install
npm run lint
npm run build
```

### Vercel explainer

The explainer is a static Vercel project rooted at `explainer/`:

```bash
cd explainer
npx vercel dev --local --listen 127.0.0.1:4173
npx vercel link --project agent-canary-explainer --yes
npx vercel --prod --yes
```

The folder intentionally contains only `explainer.html` and `vercel.json` in Git. Local Vercel metadata and `.env.local` files must remain ignored.

## 11. Validation

The current validation commands are:

```bash
cd canary
npm run lint
npm run build

cd ../cyber-redteam-foundry
uv run --extra dev pytest tests/test_api.py tests/test_auth.py
```

The focused backend suite covers API/auth behavior and URL target detail routing. Live production checks have verified the dashboard proxy, AWS backend health, campaign history, target coverage, target trends, and persisted LLM telemetry.

## 12. Design patterns

- **Orchestrator:** `GraphOrchestrator` owns run setup, checkpoint invocation, and persistence.
- **Scatter-gather:** LangGraph `Send()` fans out independent attacker branches and gathers their deltas at the evaluator barrier.
- **Strategy:** each `StrategyType` selects one scoped attack technique behind the common attacker contract.
- **Adapter:** `HttpTargetAdapter` normalizes HTTP request templates, auth headers, response paths, and observations.
- **Reducer:** `Annotated[..., operator.add]` merges parallel branch results and log events.
- **Checkpoint:** SQLite-backed LangGraph state uses the campaign ID as `thread_id`.
- **Proxy:** Vercel server functions isolate the browser from the AWS API credential.

## License

MIT. See [LICENSE](LICENSE).
