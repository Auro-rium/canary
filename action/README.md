# Agent Canary GitHub Action

Canary is repository-native security CI for an HTTP AI agent. Commit a
`canary.yaml`, deploy or start a preview endpoint, then run the Action after
that endpoint is ready. It uses the existing LangGraph red-team engine,
compares the commit with the last passing `main` baseline, uploads immutable
JSON/Markdown evidence, and fails only when the gate returns `block`.

```yaml
- name: Agent Canary
  uses: Auro-rium/canary/action@main
  with:
    api-url: ${{ secrets.CANARY_API_URL }}
    api-token: ${{ secrets.CANARY_API_TOKEN }}
    target-url: ${{ needs.preview.outputs.agent_url }}
```

The action identifies the project from `github.repository`; no project ID,
dashboard registration, or browser credential is required.

For a locally started agent, provide a command and health endpoint:

```yaml
- uses: Auro-rium/canary/action@main
  with:
    api-url: ${{ secrets.CANARY_API_URL }}
    api-token: ${{ secrets.CANARY_API_TOKEN }}
    target-url: ${{ vars.PUBLIC_PREVIEW_AGENT_URL }}
    start-command: uvicorn app.main:app --host 0.0.0.0 --port 8080
    health-url: http://127.0.0.1:8080/health
```

`start-command` verifies the local process; `target-url` must still be a
public preview URL for a hosted Canary API to reach. Use a deployment output
for the normal production path.

Artifacts contain:

- `report.json` — decision, baseline comparison, canonical findings and full evidence
- `report.md` — GitHub-readable summary with attack input, target response/tool trace, deterministic detector and LLM-judge scores
- `release-request.json` — exact non-secret CI contract submitted to Canary
- `agent.log` — when `start-command` was supplied
