# Agent Canary — Frontend Dashboard 🐤🖥️

[![React 19](https://img.shields.io/badge/React-19-61dafb.svg)](https://react.dev/)
[![Vite 8](https://img.shields.io/badge/Vite-8-646cff.svg)](https://vite.dev/)
[![TypeScript 6](https://img.shields.io/badge/TypeScript-6-3178c6.svg)](https://www.typescriptlang.org/)
[![TailwindCSS 3](https://img.shields.io/badge/TailwindCSS-3-38bdf8.svg)](https://tailwindcss.com/)

Real-time red-team telemetry and audit dashboard for the **Cyber Red Team Foundry**. Agent Canary provides a premium, interactive web interface for launching attack campaigns, monitoring live security assessments, and reviewing detailed audit reports — all from the browser.

---

## 🏗️ Architecture

```
canary/
├── index.html              # HTML entry point (JetBrains Mono font loaded)
├── vite.config.ts           # Vite build configuration
├── tailwind.config.js       # TailwindCSS design system
├── postcss.config.js        # PostCSS pipeline
├── Dockerfile               # Multi-stage build → nginx for production
├── nginx.conf               # Reverse-proxy config (/api/* → backend)
├── package.json             # Dependencies & scripts
├── tsconfig.json             # TypeScript project references
└── src/
    ├── main.tsx             # React 19 DOM mount
    ├── App.tsx              # Root app — page routing (home ↔ audit)
    ├── App.css              # App-level styles
    ├── index.css            # Global design tokens & utilities
    ├── components/
    │   ├── Navbar.tsx       # Top navigation bar with branding & actions
    │   └── Hero.tsx         # Landing page hero section with CTA
    └── pages/
        └── RunAuditPage.tsx # Full-featured audit campaign dashboard
```

---

## ⚡ Tech Stack

| Layer         | Technology                                |
| :------------ | :---------------------------------------- |
| **Framework** | React 19 with TypeScript 6                |
| **Bundler**   | Vite 8 (HMR, ESBuild transforms)         |
| **Styling**   | TailwindCSS 3 + custom CSS               |
| **Typography**| JetBrains Mono (Google Fonts)             |
| **Linting**   | Oxlint (Oxc-based, zero-config)           |
| **Serving**   | nginx 1.25 (production) / Vite dev server |

---

## 🧩 Key Components

### `Navbar`
Top navigation bar with the Agent Canary branding and a **Run Audit** action button to launch the campaign dashboard.

### `Hero`
Premium landing page hero section with dynamic animations, a glowing CTA button, and a description of the platform's capabilities.

### `RunAuditPage`
The core dashboard page for executing and monitoring red-team campaigns:
- **Campaign Configuration** — Select target, strategies, and intensity.
- **Live Telemetry** — Real-time attack progress, severity indicators, and response logs.
- **Analysis Reports** — Detailed vulnerability findings, patches, and safety scores.
- **Incident Feed** — Live stream of security events from the backend API.

---

## 🔌 Environment Variables

The frontend communicates with the FastAPI backend via environment variables injected at build time:

| Variable           | Description                                          | Default |
| :----------------- | :--------------------------------------------------- | :------ |
| `VITE_API_URL`     | Base URL for the red-team backend API                | `""`    |
| `VITE_API_TOKEN`   | Bearer token for API authentication (matches `API_SECRET_KEY` in backend) | —       |

When `VITE_API_URL` is empty (default for Docker), the frontend uses relative paths (`/api/*`), which nginx reverse-proxies to the backend service.

---

## 🚀 Getting Started

### Prerequisites
- **Node.js** ≥ 20
- **npm** ≥ 10

### Installation
```bash
cd canary/canary
npm install
```

### Development Server
```bash
npm run dev
# → http://localhost:5173

# Custom port:
npm run dev -- --port 5174
# → http://localhost:5174
```

### Production Build
```bash
npm run build
# Output: dist/
```

### Preview Production Build
```bash
npm run preview
```

### Linting
```bash
npm run lint
```

---

## 🐳 Docker Deployment

The frontend uses a **multi-stage Docker build**:

1. **Stage 1 (Builder)**: Installs dependencies, injects `VITE_API_URL` and `VITE_API_TOKEN` as build args, and runs `npm run build`.
2. **Stage 2 (Server)**: Copies the `dist/` output into an nginx container and applies the `nginx.conf` reverse-proxy rules.

```bash
# Standalone build
docker build -t canary-frontend \
  --build-arg VITE_API_URL="" \
  --build-arg VITE_API_TOKEN="your-token" \
  .

# Or via docker compose (from repo root):
docker compose up -d canary-frontend
```

**Production port**: `8000` (nginx serves SPA + proxies `/api/*` to backend on port `8001`).

---

## 📡 API Integration

The dashboard communicates with the red-team backend via these endpoints:

| Method | Endpoint                          | Purpose                           |
| :----- | :-------------------------------- | :-------------------------------- |
| `GET`  | `/api/status`                     | Health check & system status      |
| `POST` | `/api/runs`                       | Launch a new attack campaign      |
| `GET`  | `/api/runs/{run_id}`              | Poll campaign progress & state    |
| `GET`  | `/api/runs/{run_id}/analysis-report` | Fetch full analysis report     |
| `GET`  | `/api/open-findings`              | List unresolved vulnerabilities   |
| `POST` | `/api/runs/{run_id}/apply`        | Mark patches as applied           |
| `GET`  | `/api/incidents`                  | Live incident telemetry feed      |

All requests include a `Bearer <VITE_API_TOKEN>` header for authentication.

---

## 🧪 Scripts Reference

| Script          | Command              | Description                        |
| :-------------- | :------------------- | :--------------------------------- |
| `dev`           | `vite`               | Start Vite dev server with HMR     |
| `build`         | `tsc -b && vite build` | Type-check + production bundle   |
| `lint`          | `oxlint`             | Run Oxlint static analysis         |
| `preview`       | `vite preview`       | Preview production build locally   |
