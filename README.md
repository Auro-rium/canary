# Agent Canary

[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776ab?logo=python&logoColor=white)](https://www.python.org/)
[![React 19](https://img.shields.io/badge/React-19-61dafb?logo=react&logoColor=black)](https://react.dev/)
[![NVIDIA Nemotron](https://img.shields.io/badge/NVIDIA-Nemotron-76B900?logo=nvidia&logoColor=white)](https://build.nvidia.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Multi--Agent-7c3aed)](https://github.com/langchain-ai/langgraph)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ed?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Autonomous AI red-team platform. Point it at any HTTP-based AI agent, and a LangGraph pipeline dispatches selected attack strategies in parallel, evaluates target responses, and streams live results to a React dashboard. Vulnerabilities are triaged manually — no auto-remediation.

![Agent Canary demo: launching a campaign, live SSE agent topology, findings report, and Findings page](demo/demo.gif)

Full-length recording: [demo/demo.mp4](demo/demo.mp4)

---

## Deployed Demo

The production deployment is split into two services:

- **Presentation:** [agent-canary-explainer.vercel.app](https://agent-canary-explainer.vercel.app/)
- **Interactive dashboard:** [canary-coral.vercel.app](https://canary-coral.vercel.app/)
- **AWS FastAPI backend:** [Swagger docs](http://3.108.23.172/docs)

AWS exposes only FastAPI. The React dashboard runs on Vercel and reaches the backend through a server-side proxy; the API bearer token is never bundled into the production browser build. The AWS host root intentionally returns FastAPI `404 Not Found` because it is not a second frontend.

---

## Repository Layout

```
canary/
├── docker-compose.yml             # Local Docker stack: dashboard + backend
├── docker-compose.aws.yml         # AWS override: backend only on port 80
├── canary/                        # React 19 + TypeScript + Vite 8 dashboard  → canary/README.md
├── cyber-redteam-foundry/         # FastAPI + LangGraph red-team engine        → cyber-redteam-foundry/README.md
│   └── src/                       # Backend package; targets are external HTTP agents
├── runs/                          # SQLite DBs, logs (git-ignored)
└── reports/                       # Generated audit reports (git-ignored)
```

---

## Architecture

Four specialized agents run as a stateful LangGraph pipeline through NVIDIA's OpenAI-compatible Nemotron endpoint.

```mermaid
graph TD
    START([Start Campaign]) --> strategist["1 · Strategist<br/>Dispatches all selected parallel branches"]
    strategist -.->|Send| attacker["2 · Attacker branch<br/>Nemotron<br/>Builds &amp; fires adversarial prompts"]
    attacker --> target["Target Agent<br/>HTTP endpoint under test"]
    target --> evaluator["3 · Evaluator<br/>Nemotron<br/>Det. detectors + LLM judge"]
    evaluator --> branch{Vulnerability found<br/>and iterations remain?}

    branch -->|Yes — re-dispatch| strategist
    branch -->|No| reporter["4 · Reporter<br/>Nemotron<br/>Markdown + JSON audit report"]

    reporter --> END([Persist findings])

    style START  fill:#10b981,stroke:#047857,color:#fff
    style END    fill:#6366f1,stroke:#4f46e5,color:#fff
    style target fill:#f59e0b,stroke:#d97706,color:#fff
    style branch fill:#3b82f6,stroke:#2563eb,color:#fff
```

### Agent roles

| Agent | Model | Responsibility |
|---|---|---|
| Strategist | Deterministic graph node | Preserves the requested strategy order and dispatches all selected branches |
| Attacker | NVIDIA Nemotron | Constructs adversarial prompts, executes them against the target |
| Evaluator | NVIDIA Nemotron | Deterministic detectors + LLM judge; produces 4-case consensus verdict and owns iterate-vs-report routing |
| Reporter | NVIDIA Nemotron | Structured Markdown and JSON audit reports with per-finding evidence |

---

## Targeting Any HTTP Agent

Agent Canary ships an `HttpTargetAdapter` that wraps any HTTP endpoint implementing a simple chat interface. Pass the URL as `--target-id`:

```bash
cyber-rt run --target-id http://your-agent.internal/chat --strategies prompt_injection,tool_misuse
```

The adapter:
- POSTs `{"message": "<adversarial prompt>"}` to the endpoint
- Forwards an optional `TARGET_API_KEY` as `Authorization: Bearer <key>`
- Reads the response text from the first present field: `response`, `output`, `content`, or `text`

No SDK changes required. Any agent that accepts a POST with a `message` field and returns a JSON response with any of those fields is a valid target.

---

## Attack Strategies

12 strategies, each mapped to ASI and MITRE ATLAS taxonomy via `configs/asi_taxonomy.yaml`:

| Strategy | Description |
|---|---|
| `prompt_injection` | Direct instruction hijacking, system prompt extraction |
| `indirect_injection` | Payload delivered via tool output (documents, APIs, DB records) |
| `jailbreak` | Bypasses LLM-level safety guardrails |
| `tool_misuse` | RCE via calculator functions, shell commands, path traversal |
| `memory_poisoning` | Inserts false premises or malicious rules into agent memory |
| `retrieval_poisoning` | Extracts index credentials, document IDs, or raw source chunks from vector stores |
| `sensitive_data_exposure` | Extracts PII, SSNs, connection strings, API keys |
| `workflow_manipulation` | Forces the agent to skip authorization steps or approve unauthorized operations |
| `agent_handoff_corruption` | Hijacks messages between sub-agents in multi-agent pipelines |
| `authorization_boundary` | Privilege escalation, cross-account data access |
| `instruction_hierarchy` | Overrides developer system instructions with user-level input |
| `context_isolation` | Breaches document context to access unauthorized files |

**Taxonomy mapping:** ASI01–ASI10 (AI Security Intelligence classes) and ATLAS techniques (e.g. `AML.T0051.002`). Lookup table: `configs/asi_taxonomy.yaml`. Per-class confidence thresholds: `configs/thresholds.yaml`.

---

## Evaluation System

Two layers produce a 4-case consensus verdict per attempt:

**Layer 1 — Deterministic detectors**
Regex and pattern matching for PII, credentials, prompt injection, tool abuse, memory violations, RAG probing.

**Layer 2 — LLM judge (NVIDIA Nemotron)**
Semantic confidence scoring against attack strategy success criteria.

| Detector | LLM | Verdict |
|---|---|---|
| Hit | Hit | confirmed (high confidence) |
| Hit | Inconclusive | confirmed (medium confidence) |
| Miss | Hit | unconfirmed (low — requires review) |
| Miss | Miss | inconclusive (no finding created) |

---

## Storage

SQLite database at `runs/redteam.db`, three tables:

| Table | Purpose |
|---|---|
| `findings` | Deduplicated by `sha256(target:component:strategy:asi_class)[:16]`. Lifecycle: `open → wont_fix \| false_positive` (manual triage, requires reviewer_id + rationale) |
| `evaluator_verdicts` | Full audit trail — every attempt, score, confidence, verdict |
| `attack_traces` | Raw adversarial inputs (pre-sanitization), tool calls, full responses |

Semantic deduplication via `sentence-transformers all-MiniLM-L6-v2` (cosine similarity ≥ 0.92 suppresses near-duplicate findings).

---

## REST API

Backend runs on port **8001**. All endpoints require `Authorization: Bearer <API_SECRET_KEY>`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/status` | Health check — API, database, report output |
| `POST` | `/api/runs` | Start a campaign |
| `GET` | `/api/runs/{run_id}` | Campaign state and telemetry |
| `GET` | `/api/runs/{run_id}/analysis-report` | Frontend-shaped analysis with traces |
| `GET` | `/api/runs/{run_id}/findings` | Findings for a specific run |
| `GET` | `/api/open-findings` | All unresolved findings across runs |
| `GET` | `/api/incidents` | Live incident feed |
| `GET` | `/api/findings` | Paginated findings (filters: `severity`, `status`, `asi_class`) |
| `GET` | `/api/findings/{finding_id}` | Single finding detail |
| `GET` | `/api/findings/{finding_id}/attempts` | All attempts for a finding |
| `PUT` | `/api/findings/{finding_id}/status` | Update finding lifecycle status |
| `GET` | `/api/targets/{target_id}/coverage` | ASI coverage map for a target |
| `GET` | `/api/targets/{target_id}/trends` | Attack trend data for a target |
| `POST` | `/api/campaigns/run` | Start campaign with SSE streaming |

Swagger UI: `http://localhost:8001/docs` (or via nginx proxy at `http://localhost:8000/api/docs`).

---

## Dashboard

React 19 SPA served on port **8000**, four pages:

| Page | Description |
|---|---|
| Run Audit | Configure and launch campaigns. Live SSE stream with agent topology diagram. |
| Findings | Paginated findings table with verdict badges, severity, status lifecycle controls. |
| Red Team | Live incident feed, run detail, target observations, and strategy labels. |

---

## Quick Start (Local Docker)

**Prerequisites:** Docker Desktop (or Engine + Compose plugin), an NVIDIA API key, and an authorized HTTP agent target.

```bash
# 1. Clone
git clone <repo-url> canary && cd canary

# 2. Backend environment
cp cyber-redteam-foundry/.env.example cyber-redteam-foundry/.env
# Edit cyber-redteam-foundry/.env — see Environment Variables section below

# 3. Build and start
docker compose up -d --build

# 4. Open the dashboard
open http://localhost:8000
```

For an AWS backend-only deployment, use the AWS override instead:

```bash
docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d --build redteam-backend
```

### Docker services

| Service | Host port | Description |
|---|---|---|
| `canary-frontend` | 8000 | nginx serving React SPA; proxies `/api/*` to the backend |
| `redteam-backend` | 8001 | FastAPI + LangGraph orchestrator |
| `target-agent` | 9000 | CompanyBot — LangChain ReAct agent for testing |

---

## Environment Variables

### `cyber-redteam-foundry/.env`

```env
# NVIDIA NIM / build.nvidia.com
NVIDIA_API_KEY=""
NVIDIA_BASE_URL="https://integrate.api.nvidia.com/v1"
NVIDIA_MODEL="nvidia/nemotron-3-ultra-550b-a55b"

# API authentication — Bearer token for all /api/* endpoints
API_SECRET_KEY="change-me"

# Authorization scope — comma-separated target_ids allowed for runs
# Empty = no allowlist enforced
ALLOWED_TARGETS=""
REQUIRE_TARGET_ALLOWLIST=false

# Target configuration
TARGET_MODE="http"
TARGET_ENDPOINT=""            # e.g. https://your-owned-agent.example/chat
TARGET_API_KEY=""             # forwarded as Bearer token to target

# Logging
LOG_LEVEL="INFO"
LOG_FILE="runs/cyber_redteam.log"

# Storage
DB_PATH="runs/redteam.db"

# Reports
REPORT_OUTPUT_DIR="reports"
REPORT_FORMAT="markdown"      # markdown | json | both

# Run limits
MAX_RETRIES=3
TIMEOUT_SECONDS=30
DETERMINISTIC_SEED=42
```

### Vercel production environment

The Vercel dashboard uses server-only variables:

```env
CANARY_API_URL=http://<aws-elastic-ip>
CANARY_API_TOKEN=<same value as API_SECRET_KEY>
```

Do not commit a root `.env` or put an API token in a `VITE_*` variable.

---

## Local Development (without Docker)

**Backend**

```bash
cd cyber-redteam-foundry
uv venv --python 3.11 && source .venv/bin/activate
uv pip install -e ".[dev]"
cp .env.example .env   # fill in credentials
cyber-rt init          # create DB, directories, log config
cyber-rt server --port 8001
```

**Frontend**

```bash
cd canary
npm install
npm run dev
# → http://localhost:5173
```

**Run a campaign from the CLI**

```bash
# Single strategy
cyber-rt run --target-id https://your-owned-agent.example/chat --strategies prompt_injection

# Multi-strategy
cyber-rt run \
  --target-id https://your-owned-agent.example/chat \
  --strategies prompt_injection,tool_misuse,retrieval_poisoning \
  --max-attempts 5 \
  --max-iterations 3

# Diagnostics
cyber-rt doctor          # verify runtime configuration
cyber-rt list-strategies # show all strategies with severity defaults
cyber-rt status          # summary of last run
cyber-rt graph           # print Mermaid diagram of the LangGraph workflow
```

---

## Subproject Documentation

- [`canary/README.md`](canary/README.md) — React dashboard: component map, Vite config, nginx proxy setup
- [`cyber-redteam-foundry/README.md`](cyber-redteam-foundry/README.md) — Backend engine: LangGraph state machine, agent implementations, CLI reference, API detail

---

## License

[MIT](https://opensource.org/licenses/MIT)
