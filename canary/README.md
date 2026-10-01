# Agent Canary Dashboard

React 19 + TypeScript + Vite + Tailwind dashboard for the Agent Canary engine. It talks to the FastAPI backend over REST and Server-Sent Events. No UI component library; everything is hand-built.

## Pages

| Route | Purpose |
|---|---|
| `/` | Overview with live aggregate metrics |
| `/campaigns` | Campaign history with target and status filters |
| `/campaigns/new` | Configure an authorized target (URL, headers, request template, response path), pick techniques, stream the run over SSE |
| `/campaigns/:runId` | Full evidence: prompts, replies, HTTP observations, evaluator verdicts, linked findings, report, LLM telemetry |
| `/findings` | Filter by severity, status and ASI class; manual triage with reviewer and rationale |
| `/targets`, `/targets/:targetId` | Target portfolio, ASI coverage, strategy trends |

## Development

```bash
npm install
npm run dev        # http://localhost:5173, proxies /api to the backend on :8001
npm run lint
npm run build      # tsc -b && vite build
```

## Configuration

| Variable | Purpose |
|---|---|
| `VITE_API_URL` | Backend base URL. Empty means relative `/api` (nginx or Vite proxy). |
| `VITE_API_TOKEN` | Bearer token for direct local development. It is baked into the bundle, so never use it on a public deployment. |

**Docker:** the multi-stage `Dockerfile` builds the app and serves it with nginx on port 80 (8000 via compose), proxying `/api/*` to `redteam-backend:8001` with buffering off for SSE.

**Vercel:** deploy this folder. The functions in `api/` proxy `/api/*` to `CANARY_API_URL` and attach `CANARY_API_TOKEN` server-side, so the browser never sees the token.
