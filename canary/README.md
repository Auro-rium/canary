# Agent Canary

[![React 19](https://img.shields.io/badge/React-19-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6.svg)](https://www.typescriptlang.org/)
[![Vite 8](https://img.shields.io/badge/Vite-8-646cff.svg)](https://vite.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3-38bdf8.svg)](https://tailwindcss.com/)
[![nginx](https://img.shields.io/badge/nginx-1.25--alpine-009639.svg)](https://nginx.org/)
[![Docker](https://img.shields.io/badge/Docker-multi--stage-2496ed.svg)](https://www.docker.com/)

Real-time frontend dashboard for the **Cyber Red Team Foundry** backend. Communicates over REST and Server-Sent Events. Built with React 19 + TypeScript + Vite 8, styled with pure TailwindCSS and JetBrains Mono typography, and served via nginx in production.

---

## Pages

### RunAuditPage — `/audit`

Campaign launch and live monitoring.

- Configure target URL, attack strategy, and intensity level.
- Submits `POST /api/campaigns/run` and opens an SSE stream to receive live events.
- Renders a 6-node agent topology diagram (orchestrator, attacker, evaluator, defender, target, findings store) with animated edges during an active run.
- Three sequential phases: **CONFIG → RUNNING → FINDINGS REPORT**.
- Final report surfaces `campaign_id`, `run_id`, critical/high/total finding counts, duration, and target.
- Falls back to a client-side mock simulation when `VITE_API_TOKEN` is not set.

**SSE event types** emitted by `POST /api/campaigns/run`:

| Event | Payload summary |
|---|---|
| `agent_state` | Agent name + current state (idle, active, complete) — drives topology animation |
| `log` | Free-text log line from any agent |
| `finding` | Structured finding: id, severity, title, description |
| `campaign_complete` | Terminal event: campaign_id, run_id, summary counts, duration |

### FindingsPage — `/findings`

Paginated findings review with status management.

- Lists findings from `GET /api/findings` with filter controls: `severity`, `status`, `asi_class`.
- Each card includes a `VerdictBadge` that lazy-fetches `GET /api/findings/{id}` and renders verdict, confidence score, and verdict path.
- Status transition panel posts `PUT /api/findings/{id}/status` with `reviewer_id` and `rationale`.
- Attempts table sourced from `GET /api/findings/{id}/attempts`.

### RedTeamPage — `/redteam`

Live incident feed and run detail panel.

- Polls `GET /api/incidents` every 30 seconds for the live incident feed.
- Row click opens a detail panel sourced from `GET /api/runs/{run_id}`.
- Attacks table shows humanized strategy labels and 8-character `finding_id` values.
- Finding IDs link back to FindingsPage for cross-reference.

### DefensesPage — `/defenses`

ASI coverage and attack trend visualization.

- 10-cell ASI coverage grid sourced from `GET /api/targets/{id}/coverage`.
- Attack trend bar charts sourced from `GET /api/targets/{id}/trends`.

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
    ├── App.tsx              # Router: /, /audit, /findings, /redteam, /defenses
    ├── components/
    │   ├── Navbar.tsx
    │   └── Hero.tsx
    └── pages/
        ├── RunAuditPage.tsx
        ├── FindingsPage.tsx
        ├── RedTeamPage.tsx
        └── DefensesPage.tsx
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
| `VITE_API_TOKEN` | Bearer token; must match `API_SECRET_KEY` on the backend | — |

When `VITE_API_URL` is empty (the default), all `/api/*` requests are relative and nginx routes them to `redteam-backend:8001`. In dev, Vite's proxy handles the same routing to `http://localhost:8001`.

All requests include `Authorization: Bearer <VITE_API_TOKEN>`.

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

Create `.env.local` and set `VITE_API_TOKEN` to authenticate against a running backend instance. Without a token, `RunAuditPage` runs the built-in client-side mock simulation instead.

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

All requests are authenticated with `Authorization: Bearer <VITE_API_TOKEN>`.

| Method | Endpoint | Page |
|---|---|---|
| `GET` | `/api/status` | All pages (health check) |
| `POST` | `/api/campaigns/run` (SSE) | RunAuditPage |
| `GET` | `/api/findings` | FindingsPage |
| `GET` | `/api/findings/{id}` | FindingsPage |
| `GET` | `/api/findings/{id}/attempts` | FindingsPage |
| `PUT` | `/api/findings/{id}/status` | FindingsPage |
| `GET` | `/api/incidents` | RedTeamPage |
| `GET` | `/api/runs/{run_id}` | RedTeamPage |
| `GET` | `/api/targets/{id}/coverage` | DefensesPage |
| `GET` | `/api/targets/{id}/trends` | DefensesPage |
