# Agent Canary

**CI for AI-agent security. Every pull request gets attacked before it ships.**

Traditional CI catches code regressions. Canary catches AI-agent behavior
regressions. It tells you whether the agent you are about to ship is less
secure than the one you already trust.

```
PR / push
  -> preview agent
  -> Canary red-team campaign
  -> accepted-baseline replay
  -> differential evidence
  -> PASS / WARN / BLOCK
  -> GitHub job summary and check
```

Canary is an evolution of the existing LangGraph red-team engine. The CUTC
release layer adds projects, verified target contracts, explicit
environment-specific baselines, reusable attack-case identities, differential
classification, policy gates, release evidence, and the GitHub Action.

## 30-second demo

The demo target is the deliberately vulnerable CompanyBot in
`cyber-redteam-foundry/target_agent`. Run the real API and target locally:

```bash
cp cyber-redteam-foundry/.env.example cyber-redteam-foundry/.env
docker compose up --build
```

Then configure a preview endpoint in `canary.yaml`, run the first assessment,
and explicitly accept its completed release as the `preview` baseline in the
Projects page. A candidate that leaks employee data or performs an
unauthorized calculator action is classified as a new regression and returns
`BLOCK`; after the fix, the same case returns `PASS`.

The action is reusable from another repository:

```yaml
- uses: Auro-rium/canary/action@feature/cutc-2026-differential-gate
  with:
    api-url: ${{ secrets.CANARY_API_URL }}
    api-token: ${{ secrets.CANARY_PROJECT_TOKEN }}
    target-url: ${{ steps.preview.outputs.url }}
    target-verification-token: ${{ secrets.CANARY_TARGET_VERIFICATION_TOKEN }}
```

Keep the token in GitHub Actions secrets. It is never bundled into the React
application.

Create a scoped token once with an authenticated administrator request:

```bash
curl -X POST "$CANARY_API_URL/api/projects/$PROJECT_ID/tokens" \
  -H "Authorization: Bearer $API_SECRET_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"scopes":["release:create","release:read"]}'
```

Store the returned value as `CANARY_PROJECT_TOKEN`; it is hash-only at rest and
accepted only by the CI release endpoint for its authorized project.

## How the security gate works

Each release is tied to a commit, target endpoint, environment, run, policy,
scores, coverage, and evidence. Canary never silently treats the first
completed run as trusted. A person or an explicit safe policy must accept a
completed release as the baseline for that environment.

For every stable attack case:

| Baseline | Candidate | Classification |
|---|---|---|
| safe | vulnerable | **regression** (normally BLOCK) |
| vulnerable | vulnerable | known finding |
| vulnerable | safe | resolved |
| safe | safe | clean |

The evaluator remains authoritative: deterministic detector signals and the
semantic judge are retained with confidence, severity, rationale, response
text, and taxonomy evidence. Attackers do not declare their own success.

Gate policy is explicit:

```yaml
gate:
  block_on: [critical, high]
  warn_on: [medium, low]
  max_new_blocking_findings: 0
  max_new_nonblocking_findings: null
```

Known baseline vulnerabilities do not become new blockers. Coverage measures
executed configured security surface, not the number of vulnerabilities found.

## Architecture

```text
GitHub PR
   |
GitHub Action (server-side project token)
   |
Canary API -> durable release/job state
   |
accepted baseline + candidate target
   |
LangGraph: Strategist -> parallel Attackers -> Evaluator -> Reporter
   |
attack evidence and reusable attack cases
   |
differential engine -> policy gate -> PASS/WARN/BLOCK
   |
GitHub summary + release evidence dashboard
```

The backend is FastAPI, SQLAlchemy, SQLite for local/demo deployments, and
LangGraph. The frontend is React, TypeScript, Vite, Tailwind, and a same-origin
server-side API proxy. Existing campaign, findings, console, SSE, and report
capabilities remain available.

## API

Core product endpoints:

```text
POST   /api/projects
GET    /api/projects
GET    /api/projects/{project_id}
POST   /api/projects/verify-target
POST   /api/projects/{project_id}/target/verify
GET    /api/projects/{project_id}/baselines
POST   /api/projects/{project_id}/baselines/{release_id}/accept
POST   /api/projects/{project_id}/releases
GET    /api/projects/{project_id}/releases
GET    /api/releases/{release_id}
GET    /api/releases/{release_id}/regressions
POST   /api/ci/releases
```

The CI endpoint accepts repository, commit, environment, endpoint, strategy,
and gate configuration. It returns a release ID for polling. A release remains
`queued`, `running`, `completed`, `failed`, or `cancelled`.

## Local development

Backend:

```bash
cd cyber-redteam-foundry
uv sync --extra dev
uv run uvicorn cyberredteam.api:app --host 0.0.0.0 --port 8001
uv run pytest -q
```

Frontend:

```bash
cd canary
npm ci
npm run dev
npm run build
npm run lint
```

The local dashboard uses `/api` through the Vite proxy. Hosted deployments
should set `CANARY_API_URL` and `CANARY_API_TOKEN` only on the server-side
proxy, never as a `VITE_*` variable.

## Security model and limitations

Target validation allows only HTTP(S), rejects localhost, private, link-local,
reserved, multicast, unspecified, metadata, userinfo, and redirect-bypass
forms, and disables redirects during verification. Production deployments
should additionally enforce outbound network egress controls.

The checked-in local adapter still uses SQLite and an API process thread for
compatibility with the original project. The release lifecycle is now modeled
as a durable, idempotent job boundary and is ready for a queue/worker adapter;
PostgreSQL/Redis deployment wiring remains a production follow-up. Dashboard
read access is proxied server-side; CI credentials are separate from browser
JavaScript.

## CUTC 2026 build

Built specifically for CUTC:

- differential baseline-vs-candidate evaluation and stable attack-case IDs
- explicit accepted baselines per environment
- release lifecycle, gate policy, scores, coverage, and persisted regressions
- SSRF-resistant target validation and token/verification primitives
- GitHub Action outputs and job-summary evidence
- release-oriented dashboard components and baseline workflow
- deterministic coverage and regression tests

The underlying four-agent red-team engine predates CUTC and remains intact.
