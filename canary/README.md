# Agent Canary

[![React 19](https://img.shields.io/badge/React-19-61dafb.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6.svg)](https://www.typescriptlang.org/)
[![Vite 8](https://img.shields.io/badge/Vite-8-646cff.svg)](https://vite.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3-38bdf8.svg)](https://tailwindcss.com/)
[![nginx](https://img.shields.io/badge/nginx-1.25--alpine-009639.svg)](https://nginx.org/)
[![Docker](https://img.shields.io/badge/Docker-multi--stage-2496ed.svg)](https://www.docker.com/)

Read-only release-evidence dashboard for the **Cyber Red Team Foundry** backend, built with React 19 + TypeScript + Vite 8. CI owns attack execution; the browser never holds a Canary bearer token.

---

## Pages

### RunAuditPage — `/audit`

Historical campaign monitoring. Production attack launches happen in GitHub Actions.

- Submits `POST /api/campaigns/run` with target URL, attack strategies, and intensity.
- Opens SSE stream for live events; renders 4-node agent topology with animated edges.
- Three phases: **CONFIG → RUNNING → REPORT**.
- Final report: campaign_id, run_id, finding counts (by severity), duration, target.
- The public deployment does not simulate results when API access is unavailable.

**SSE event types** emitted by `POST /api/campaigns/run`:

| Event | Payload summary |
|---|---|
| `agent_state` | Agent name + current state (idle, active, complete) — drives topology animation |
| `log` | Free-text log line from any agent |
| `finding` | Structured finding: id, severity, title, description |
| `campaign_complete` | Terminal event: campaign_id, run_id, summary counts, duration |

### FindingsPage — `/findings`

Paginated findings review with status management.

- Filters by `severity`, `status`, `asi_class`.
- Verdict badges lazy-fetch details and render confidence score + verdict path.
- Status transitions (`PUT /api/findings/{id}/status`) require `reviewer_id` + `rationale`.
- Attempts table from `GET /api/findings/{id}/attempts`.

### RedTeamPage — `/redteam`

Live incident feed and run detail panel.

- Polls `GET /api/incidents` every 30 seconds.
- Row click opens detail panel from `GET /api/runs/{run_id}`.
- Attacks table with humanized strategy labels and finding IDs (linkable to FindingsPage).

### Console — `/console`

Chat command interface for driving campaigns and querying results, with live agent-graph visualization.

- Three-panel layout: run history sidebar, chat panel, live agent graph.
- Pattern-matched commands (no LLM):

  | Command | Effect |
  |---|---|
  | `connect <url>` | Set target endpoint |
  | `run <slug,slug>` \| `run all` | Launch campaign (SSE) |
  | `show findings` \| `incidents` \| `coverage` \| `trends` \| `run <id>` | Query endpoints |
  | `re-run last` | Replay previous campaign |
  | `export` | Download report as JSON |
  | `help` | List all commands |

- Run history persisted to IndexedDB via `idb-keyval`.
- State managed by `zustand` store (`src/store/useConsoleStore.ts`).

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
    ├── App.tsx              # View switch: home, audit, findings, redteam, console
    ├── components/
    │   ├── Navbar.tsx
    │   ├── Hero.tsx
    │   └── console/
    │       ├── ConsoleLayout.tsx    # 3-panel shell
    │       ├── Sidebar.tsx          # run history + nav
    │       ├── ChatPanel.tsx        # command parsing + SSE dispatch
    │       └── AgentGraphPanel.tsx  # shared agent topology SVG (also used by RunAuditPage)
    ├── lib/
    │   ├── api.ts                  # single client for every backend endpoint
    │   ├── commands.ts             # chat command parser
    │   ├── db.ts                   # IndexedDB run history (idb-keyval)
    │   ├── techniques.ts           # attack technique catalogue
    │   └── types.ts                # shared domain types (Phase, FindingPayload, ...)
    ├── store/
    │   └── useConsoleStore.ts      # zustand store for Console state
    └── pages/
        ├── RunAuditPage.tsx
        ├── FindingsPage.tsx
        └── RedTeamPage.tsx
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
| `CANARY_API_URL` | Upstream backend base URL, server-side Vercel env | — |
| `CANARY_API_TOKEN` | Backend bearer token, server-side Vercel env | — |

The browser always requests its same-origin `/api/*` path. Vercel's read-only proxy injects the server-side token; Docker nginx injects `API_SECRET_KEY` into its upstream request.

No `VITE_API_TOKEN` is supported: Vite would embed it in a public JavaScript bundle.

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

For local UI work, run the Docker stack so nginx can supply the server-side API credential. The Vite server is intentionally not an authenticated production proxy.

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

The dashboard proxy authenticates server-side and permits GET/HEAD only. Every browser request is wrapped in `src/lib/api.ts`; CI writes releases through the authenticated backend API.

| Method | Endpoint | Used by |
|---|---|---|
| `GET` | `/api/status` | health check |
| `POST` | `/api/runs` | Console (`createRun`) |
| `GET` | `/api/runs/{run_id}` | RedTeamPage, Console (`show run`) |
| `GET` | `/api/runs/{run_id}/analysis-report` | Console (`getRunAnalysisReport`) |
| `GET` | `/api/runs/{run_id}/report-markdown` | RunAuditPage |
| `GET` | `/api/runs/{run_id}/findings` | Console (`getRunFindings`) |
| `GET` | `/api/open-findings` | Console (`getOpenFindings`) |
| `GET` | `/api/findings` | FindingsPage, Console (`show findings`) |
| `GET` | `/api/findings/{id}` | FindingsPage |
| `GET` | `/api/findings/{id}/attempts` | FindingsPage |
| `PUT` | `/api/findings/{id}/status` | FindingsPage |
| `GET` | `/api/targets/{id}/coverage` | Console (`show coverage`) |
| `GET` | `/api/targets/{id}/trends` | Console (`show trends`) |
| `GET` | `/api/incidents` | RedTeamPage, Console (`show incidents`) |
| `POST` | `/api/campaigns/run` (SSE) | RunAuditPage, Console (`run`) |
