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

Campaign launch/monitoring (formerly a dedicated RunAuditPage) now lives entirely in the Console — see below. It was removed once the Console covered the same SSE campaign flow and agent graph, to avoid maintaining two parallel implementations.

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

### Console — `/console`

Chat-centric command interface for launching campaigns and querying the backend, alongside a live agent-graph view. This is now the only way to run a campaign — it replaced the old dedicated RunAuditPage/config-form flow.

- Three-panel layout: run history/navigation sidebar, chat, and a live agent graph.
- Pattern-matched commands, no LLM involved:

  | Command | Effect |
  |---|---|
  | `connect <url>` | Set the target endpoint |
  | `run <slug,slug>` / `run all` | Start a campaign via `POST /api/campaigns/run` (SSE) |
  | `show findings` | `GET /api/findings` |
  | `show incidents` | `GET /api/incidents` |
  | `show coverage <target_id>` | `GET /api/targets/{id}/coverage` |
  | `show trends <target_id>` | `GET /api/targets/{id}/trends` |
  | `show run <run_id>` | `GET /api/runs/{run_id}` |
  | `re-run last` | Replay the last campaign's target/techniques |
  | `export` | Download the last completed report as JSON |
  | `help` | List commands |

- Completed campaign reports are saved to IndexedDB (via `idb-keyval`) so run history survives a page reload.
- Console state (chat log, campaign phase, agent statuses, findings) is held in a `zustand` store (`src/store/useConsoleStore.ts`), separate from the local component state used by the other pages.

**SSE event types** emitted by `POST /api/campaigns/run` and consumed by the Console:

| Event | Payload summary |
|---|---|
| `agent_state` | Agent name + current state (idle, active, complete) — drives agent-graph animation |
| `log` | Free-text log line from any agent |
| `finding` | Structured finding: id, severity, title, description |
| `campaign_complete` | Terminal event: campaign_id, run_id, summary counts, duration |

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
    ├── App.tsx              # View switch: home, findings, redteam, defenses, console
    ├── components/
    │   ├── Navbar.tsx
    │   ├── Hero.tsx
    │   └── console/
    │       ├── ConsoleLayout.tsx    # 3-panel shell
    │       ├── Sidebar.tsx          # run history + nav
    │       ├── ChatPanel.tsx        # command parsing + SSE dispatch
    │       └── AgentGraphPanel.tsx  # agent topology SVG, driven by Console state
    ├── lib/
    │   ├── api.ts                  # single client for every backend endpoint
    │   ├── commands.ts             # chat command parser
    │   ├── db.ts                   # IndexedDB run history (idb-keyval)
    │   ├── techniques.ts           # attack technique catalogue
    │   └── types.ts                # shared domain types (Phase, FindingPayload, ...)
    ├── store/
    │   └── useConsoleStore.ts      # zustand store for Console state
    └── pages/
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
| State (Console) | Zustand |
| Persistence (Console) | IndexedDB via idb-keyval |
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

Create `.env.local` and set `VITE_API_TOKEN` to authenticate against a running backend instance.

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

All requests are authenticated with `Authorization: Bearer <VITE_API_TOKEN>`. Every route below is wrapped in `src/lib/api.ts`, the single client shared by all pages and the Console — no page constructs its own fetch/auth boilerplate.

| Method | Endpoint | Used by |
|---|---|---|
| `GET` | `/api/runs/{run_id}` | RedTeamPage, Console (`show run`) |
| `GET` | `/api/findings` | FindingsPage, Console (`show findings`) |
| `GET` | `/api/findings/{id}` | FindingsPage |
| `GET` | `/api/findings/{id}/attempts` | FindingsPage |
| `PUT` | `/api/findings/{id}/status` | FindingsPage |
| `GET` | `/api/targets/{id}/coverage` | DefensesPage, Console (`show coverage`) |
| `GET` | `/api/targets/{id}/trends` | DefensesPage, Console (`show trends`) |
| `GET` | `/api/incidents` | RedTeamPage, Console (`show incidents`) |
| `POST` | `/api/campaigns/run` (SSE) | Console (`run`) |

Other backend routes (`/api/status`, `/api/runs` POST, `/api/runs/{run_id}/analysis-report`, `/api/runs/{run_id}/report-markdown`, `/api/runs/{run_id}/findings`, `/api/runs/{run_id}/apply`, `/api/open-findings`) exist on the backend but currently have no frontend caller — not wrapped in `src/lib/api.ts` to avoid dead code.
