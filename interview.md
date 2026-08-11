# Agent Canary — Interview Preparation

This guide is based on the current `main` branch. The shared AWS demo backend was terminated, so deployment answers should describe AWS as a user-provisioned deployment rather than an active shared service.

## Level 1 — Fundamentals

### 1. What is Agent Canary?

Agent Canary is an automated red-team platform for authorized HTTP-based AI agents. It generates adversarial prompts, sends them to a real target, evaluates the target's real response, and produces evidence-backed findings.

### 2. What problem does it solve?

Manual testing of AI agents is slow and inconsistent. Canary automates repeatable tests for prompt injection, tool abuse, privilege escalation, data exposure, memory poisoning, and related agent risks.

### 3. What is being attacked?

An external HTTP AI agent, not Canary itself. The target must expose a compatible HTTP endpoint, normally accepting JSON such as `{"message":"..."}` and returning a JSON response.

### 4. Is the target included in the repository?

No. The demonstration target is the separate [CompanyAgent Canary Demo](https://github.com/Auro-rium/companybot-canary-demo), a real LangChain tool-calling agent backed by Backboard.

### 5. What technologies are used?

- Python 3.11
- FastAPI
- LangGraph
- NVIDIA NIM with Nemotron
- SQLite and SQLAlchemy
- React 19, TypeScript, Vite, and TailwindCSS
- Docker Compose
- Vercel for the dashboard and explainer

### 6. What is the difference between the frontend and backend?

The React frontend starts campaigns and renders data. The FastAPI backend authenticates requests, runs the LangGraph workflow, calls NVIDIA NIM, contacts the target, evaluates responses, stores evidence, and generates reports.

### 7. Is the AWS backend currently running?

No. The shared EC2 instance was intentionally terminated. To run Canary, deploy the FastAPI backend on your own AWS host and configure Vercel's `CANARY_API_URL` and `CANARY_API_TOKEN` variables.

### 8. What does the backend expose?

FastAPI routes for campaign creation, SSE execution, campaign history, findings, target coverage, trends, dashboard overview, incidents, reports, and health status. Swagger is available at `/docs` on a deployed backend.

## Level 2 — Architecture

### 9. Describe the complete campaign lifecycle.

The request enters FastAPI, authentication and target authorization are checked, selected techniques are converted into LangGraph branches, attacker agents generate prompts, the HTTP adapter calls the target, the evaluator analyzes responses, the graph either iterates or reports, and the run plus evidence are persisted.

### 10. What are the four workflow roles?

1. Strategist: deterministic dispatch of selected techniques.
2. Attacker: Nemotron generates one scoped adversarial prompt per branch.
3. Evaluator: deterministic detectors plus a Nemotron judge score the target response.
4. Reporter: Nemotron produces Markdown and JSON reports.

### 11. Is the strategist an LLM?

Not in the default production graph. The strategist node preserves the user's explicit selection and dispatches branches deterministically. An LLM-ranked strategist implementation exists as an alternative, but it is not used by the default dispatch path.

### 12. Why make strategist selection deterministic?

It makes coverage auditable. The campaign executes what the user selected instead of silently skipping or inventing techniques. Model reasoning is reserved for prompt generation, evaluation, and reporting.

### 13. How does LangGraph provide parallelism?

`dispatch_attacker_branches()` returns multiple `Send("attacker_branch", payload)` objects. LangGraph executes those branches independently and waits at the superstep boundary before running the evaluator.

### 14. What is the scatter-gather pattern here?

The selected techniques are scattered into independent attacker branches. Their `AttackResult` objects are gathered by the evaluator after all branches complete.

### 15. How are parallel results merged safely?

Lists such as `attack_results` and log messages use LangGraph reducers based on `operator.add`. Each branch returns a single-item list, so results are appended instead of overwritten. Results also carry an explicit iteration number, preventing incorrect positional slicing.

### 16. How many branches can run in parallel?

The backend supports up to 12 parallel branches. The current dashboard exposes eight selectable techniques.

### 17. Does the system retry campaigns?

The evaluator can route the graph back to the strategist when a successful finding exists and the iteration budget remains. That creates fresh branches. Provider calls also have bounded retries for transient model or network failures.

### 18. What is the role of SQLite?

SQLite stores runs, attacks, findings, evaluator verdicts, LLM telemetry, and LangGraph checkpoints. It makes campaign evidence inspectable and allows state recovery through the campaign ID.

## Level 3 — LLM and evaluation

### 19. Which model is used?

The configured model is `nvidia/nemotron-3-ultra-550b-a55b` through NVIDIA's OpenAI-compatible NIM endpoint. The attacker, evaluator, and reporter use it. The default strategist dispatch node does not call a model.

### 20. What happens if the NVIDIA key is missing?

The factory raises an error and the campaign fails closed. Canary never replaces a failed model call with fake text or a fabricated finding.

### 21. What does the attacker model return?

Structured output containing status, capability type, ASI technique, depth, payload, rationale, mutation information, and refusal reason when applicable.

### 22. Can the attacker declare that it found a vulnerability?

No. The attacker only generates and executes the prompt. Success and score are evaluator-owned fields.

### 23. What is the deterministic evaluator layer?

It uses strategy-specific detectors for signals such as prompt leakage, credentials, PII, tool misuse, memory violations, retrieval poisoning, instruction hierarchy problems, and workflow abuse.

### 24. Why use both deterministic detectors and an LLM judge?

Detectors provide explainable, repeatable signals. The LLM judge handles semantic behavior that cannot be reliably captured by regular expressions or fixed rules. Combining both improves evidence quality while keeping the verdict auditable.

### 25. Explain the four evaluator paths.

| Detector | Judge | Result |
|---|---|---|
| Hit | Successful/non-inconclusive | Confirmed finding |
| Hit | Inconclusive | Confirmed with medium confidence |
| Miss | Successful above threshold | Unconfirmed review signal |
| Miss | Failed/inconclusive | Inconclusive or failed |

### 26. Is a failed attack a finding?

No. A blocked or failed attack is evidence that the target resisted that attempt. Canary does not infer a vulnerability from an attack category alone.

### 27. How are findings deduplicated?

The finding identity is content-addressed from target, component, strategy, and ASI class. The resulting stable ID allows the same issue to be observed across multiple campaigns without creating unrelated duplicate findings.

### 28. What is stored as evidence?

The generated prompt, target reply, HTTP status, latency, request/response observations, detector indicators, score, threshold, confidence, verdict path, rationale, hashes, and relevant LLM token/latency telemetry.

## Level 4 — HTTP and security

### 29. Why use an adapter instead of a target-specific client?

The adapter isolates target protocol differences. A target can use the default `message` contract or provide a custom JSON template and response path without changing the attack agents.

### 30. How is `{{PROMPT}}` substituted safely?

The adapter uses `json.dumps()` before substitution. That correctly escapes quotes, newlines, Unicode, and other characters inside the generated prompt.

### 31. How does the target response get extracted?

The adapter accepts a dot path such as `choices.0.message.content`. If no path is configured, it checks common response fields such as `response`, `output`, `content`, and `text`.

### 32. How is target authorization enforced?

The API requires a bearer token and can enforce an `ALLOWED_TARGETS` list with `REQUIRE_TARGET_ALLOWLIST=true`. Only configured, authorized targets should be assessed.

### 33. How are target credentials protected?

Target headers are sent by the backend and are not bundled into the browser build. API secrets, NVIDIA keys, target keys, and Vercel proxy tokens remain server-side.

### 34. Does Canary automatically fix vulnerabilities?

No. Canary reports and tracks findings. A human reviews and decides whether to fix, dismiss, or accept the risk.

### 35. What happens if an attacker branch refuses?

The branch records a refusal, sends no payload to the target, and does not use a static replacement payload.

## Level 5 — Frontend, deployment, and operations

### 36. How does live progress reach the frontend?

`POST /api/campaigns/run` returns Server-Sent Events. Events include agent state changes, logs, findings, and a final campaign-complete event. The frontend buffers event lines so split network chunks do not corrupt JSON.

### 37. Why is the AWS backend UI-free?

AWS runs only the FastAPI service. Keeping the UI on Vercel separates presentation from execution and ensures the AWS host is an API deployment rather than a second frontend.

### 38. How would you deploy it now?

Provision an AWS host, configure the backend `.env`, and run:

```bash
docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d --build redteam-backend
```

Then configure Vercel:

```env
CANARY_API_URL=http://<your-backend-host>
CANARY_API_TOKEN=<your-API_SECRET_KEY>
```

### 39. How do you run the project locally?

```bash
cp cyber-redteam-foundry/.env.example cyber-redteam-foundry/.env
docker compose up -d --build
```

The local dashboard runs on port 8000 and the backend on port 8001.

### 40. How do you test the explainer locally?

```bash
cd explainer
npx vercel dev --local --listen 127.0.0.1:4173
```

The explainer is static and does not require the backend.

### 41. What does Vercel proxy?

The Vercel server functions forward browser `/api/*` requests to the configured FastAPI backend and attach the server-side bearer token. Dynamic wrappers support campaigns, targets, and slash-containing URL target IDs.

### 42. What are the main operational failure modes?

- Missing or invalid `NVIDIA_API_KEY`.
- Backend unavailable or not configured in Vercel.
- Target authentication failure.
- Target not included in the allowlist.
- Target response shape not matching the configured response path.
- Model provider timeout or rate limit.
- SQLite/report directory permission or persistence problems.

### 43. What validation has been performed?

The frontend has passed `npm run lint` and `npm run build`. The focused backend API/auth suite has passed 16 tests, including URL target coverage/trend routing. Local Vercel CLI serving of the explainer has also been verified.

### 44. What is the biggest design limitation?

The evaluator is only as good as the target response, detector coverage, and model judgment. A black-box HTTP test cannot prove that hidden tools or private state are safe. Findings therefore require human review and should be supplemented with target-side authorization and logging tests.

### 45. Why is the system evidence-first?

AI output alone is not a reliable security claim. Canary preserves the prompt, target response, HTTP observation, detector result, evaluator path, and telemetry so a reviewer can reproduce and challenge the finding.

## Strong closing answer

> Agent Canary is a LangGraph-based red-team engine for authorized HTTP agents. The user explicitly selects attack techniques, a deterministic strategist fans them out into parallel Nemotron-powered attacker branches, and every branch sends a real prompt to the target through a generic HTTP adapter. Deterministic detectors and a Nemotron evaluator classify the actual response, while LangGraph decides whether to iterate or report. All prompts, responses, observations, verdicts, findings, reports, checkpoints, and LLM telemetry are persisted for human review. The React dashboard is hosted separately from the FastAPI backend, and the current AWS demo backend has been terminated, so deployment requires the user to provision and configure their own backend.
