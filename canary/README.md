# Agent Canary

[![React 19](https://img.shields.io/badge/React-19-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6.svg)](https://www.typescriptlang.org/)
[![Vite 8](https://img.shields.io/badge/Vite-8-646cff.svg)](https://vite.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3-38bdf8.svg)](https://tailwindcss.com/)
[![nginx](https://img.shields.io/badge/nginx-1.25--alpine-009639.svg)](https://nginx.org/)
[![Docker](https://img.shields.io/badge/Docker-multi--stage-2496ed.svg)](https://www.docker.com/)

Real-time dashboard for the **Cyber Red Team Foundry** backend, built with React 19 + TypeScript + Vite 8. Styled with TailwindCSS and JetBrains Mono, served via nginx, communicating over REST and Server-Sent Events.

Live links: [interactive dashboard](https://canary-coral.vercel.app/) · [project explainer](https://agent-canary-explainer.vercel.app/)

The previous shared AWS backend was terminated. The Vercel dashboard requires a user-provisioned FastAPI backend configured through server-side `CANARY_API_URL` and `CANARY_API_TOKEN` variables before campaign execution works.

The explainer source lives at [`explainer/`](../explainer/) in the repository. The demonstration target is the separate [CompanyAgent Canary Demo](https://github.com/Auro-rium/companybot-canary-demo), a real HTTP LangChain tool-calling agent; Canary assesses it only with authorization.

---

## Pages

### Campaigns — `/campaigns`

Paginated campaign history backed by `GET /api/runs`.

- Filters by target and lifecycle status.
- Shows persisted campaign counts, confirmed findings, timing, and LLM token totals.
- Every row links to an evidence-backed run detail page.

### New campaign — `/campaigns/new`

Authorized HTTP target configuration and live execution.

- Submits `POST /api/campaigns/run` and consumes its SSE stream.
- Validates HTTP(S) URLs, optional JSON headers, request templates, and response paths before launch.
- Supports all eight currently exposed attack strategies; the backend preserves explicit selections and supports up to 12 parallel branches.
- Clears entered target headers after launch and warns that server checkpoints may contain them.

### Campaign detail — `/campaigns/:runId`

Complete persisted evidence for one campaign.

- Polls `GET /api/runs/{run_id}` while active, then renders the authoritative terminal record.
- Provides expandable raw attacker prompts, target replies, HTTP observations, evaluator evidence, linked findings, reporter Markdown, and the full LLM token/latency ledger.

**SSE event types** emitted by `POST /api/campaigns/run`:

| Event | Payload summary |
|---|---|
| `agent_state` | Agent name + current state (idle, active, complete) — drives topology animation |
| `log` | Free-text log line from any agent |
| `finding` | Structured finding: id, severity, title, description |
| `campaign_complete` | Terminal event: campaign_id, run_id, summary counts, duration |

### Findings — `/findings`

Paginated findings review with status management.

- Filters by `severity`, `status`, `asi_class`.
- Verdict badges lazy-fetch details and render confidence score + verdict path.
- Status transitions (`PUT /api/findings/{id}/status`) require `reviewer_id` + `rationale`.
- Attempts table from `GET /api/findings/{id}/attempts`.

### Targets — `/targets` and `/targets/:targetId`

Target portfolio and coverage review.

- Shows real campaign counts, most recent status, open finding counts, ASI coverage, strategy trends, and recent campaigns.

---

## Source Layout

```
canary/
├── index.html
├── vite.config.ts           # /api proxy → http://localhost:8001 (dev)
├── tailwind.config.js
├── nginx.conf               # /api/* → redteam-backend:8001 (prod), SSE-optimized
├── Dockerfile               # Multi-stage: node build → nginx serve
├── package.json
└── src/
    ├── main.tsx
    ├── App.tsx              # Browser routes: home, campaigns, findings, targets
    ├── components/
    │   ├── Navbar.tsx
    │   ├── Hero.tsx
    │   └── Console.tsx              # shared console primitives
    ├── lib/
    │   ├── api.ts                  # single client for every backend endpoint
    │   ├── techniques.ts           # attack technique catalogue
    │   ├── types.ts                # backend-aligned domain DTOs
    │   └── presentation.ts         # shared formatting helpers
    └── pages/
        ├── CampaignsPage.tsx
        ├── CampaignNewPage.tsx
        ├── CampaignDetailPage.tsx
        ├── FindingsPage.tsx
        ├── TargetsPage.tsx
        └── TargetDetailPage.tsx
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Framework | React 19 + TypeScript |
| Bundler | Vite 8 |
| Styling | TailwindCSS 3 |
| Typography | JetBrains Mono |
| Linting | Oxlint |
| Production server | nginx 1.25-alpine |

No external UI component library. All UI is hand-built with Tailwind utility classes.

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `VITE_API_URL` | Backend base URL | `""` (relative — nginx proxies) |
| `VITE_API_TOKEN` | Optional direct-development bearer token; never set in Vercel production | — |

When `VITE_API_URL` is empty (the default), all `/api/*` requests are relative and nginx routes them to `redteam-backend:8001`. In dev, Vite's proxy handles the same routing to `http://localhost:8001`.

Vercel production requests stay relative to `/api/*`. The Vercel server-side proxy adds
`CANARY_API_TOKEN` when forwarding to `CANARY_API_URL`, so browser bundles never contain the
backend token. `VITE_API_TOKEN` is only for direct local development against an authenticated API.

---

## nginx SSE Configuration

The production nginx config applies the following settings on the `/api/campaigns/run` SSE route so events are not buffered:

```
proxy_buffering off;
proxy_cache off;
proxy_read_timeout 300s;
add_header X-Accel-Buffering no;
```

Without these, nginx's default response buffering will hold SSE frames until the buffer fills, breaking the live topology animation and log stream.

---

## Development

```bash
npm install
npm run dev        # http://localhost:5173
```

Create `.env.local` with `VITE_API_TOKEN` only when connecting directly to a development backend. Production uses the server-side Vercel proxy.

---

## Production Build

```bash
npm run build      # outputs to dist/
```

Type-checking (`tsc -b`) runs before bundling. Fix all type errors before deploying.

---

## Docker

Multi-stage build: Node 20 builds the static assets, nginx 1.25-alpine serves them.

```bash
docker build -t canary-frontend \
  --build-arg VITE_API_URL="" \
  --build-arg VITE_API_TOKEN="your-token" \
  .
```

Or bring up the full stack from the repo root:

```bash
docker compose up -d --build
```

The container serves the SPA on port **8000** and proxies `/api/*` to `redteam-backend:8001`.

---

## Scripts

| Script | Command | Description |
|---|---|---|
| `dev` | `vite` | Dev server with HMR |
| `build` | `tsc -b && vite build` | Type-check + bundle |
| `lint` | `oxlint` | Static analysis |
| `preview` | `vite preview` | Preview production build locally |

---

## API Surface

All requests are authenticated with `Authorization: Bearer <VITE_API_TOKEN>`. Every route below is wrapped in `src/lib/api.ts`.

| Method | Endpoint | Used by |
|---|---|---|
| `GET` | `/api/dashboard/overview` | HomePage |
| `GET` | `/api/runs` | CampaignsPage |
| `GET` | `/api/runs/{run_id}` | RedTeamPage |
| `GET` | `/api/runs/{run_id}/report-markdown` | RunAuditPage |
| `GET` | `/api/findings` | FindingsPage |
| `GET` | `/api/findings/{id}` | FindingsPage |
| `GET` | `/api/findings/{id}/attempts` | FindingsPage |
| `PUT` | `/api/findings/{id}/status` | FindingsPage |
| `GET` | `/api/targets` | TargetsPage |
| `GET` | `/api/targets/{target_id}/coverage` | TargetDetailPage |
| `GET` | `/api/targets/{target_id}/trends` | TargetDetailPage |
| `POST` | `/api/campaigns/run` (SSE) | RunAuditPage |
