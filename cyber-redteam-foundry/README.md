# Cyber Red Team Foundry

The Agent Canary engine: FastAPI + LangGraph, with [Backboard.io](https://backboard.io) inference. It attacks any authorized HTTP AI agent, scores responses against the OWASP agentic (ASI) / MITRE ATLAS taxonomy, and writes audit reports. Findings are triaged manually.

See the [root README](../README.md) for setup and [TECHNICAL.md](../TECHNICAL.md) for the architecture.

## Layout

```text
configs/     models.yaml (optional per-agent provider/model), asi_taxonomy.yaml,
             technique_specs.yaml, thresholds.yaml
prompts/     system prompts: strategist, attacker, evaluator, reporter, orchestrator
src/cyberredteam/
  api.py, cli.py, settings.py, schemas.py
  agents/              attacker, evaluator, reporter, strategist
  attack_strategies/   strategy registry
  evaluation/          taxonomy lookup, technique specs, scorer, metrics
  langgraph/           state, graph, nodes, orchestrator
  llm/                 backboard.py (ChatBackboard), observable.py, factory.py, schemas.py
  storage/             SQLAlchemy models + SQLiteStore
  tools/               HttpTargetAdapter + deterministic detectors
tests/
```

## Commands

```bash
uv sync --extra dev
cp .env.example .env          # set BACKBOARD_API_KEY and API_SECRET_KEY
uv run cyber-rt init          # create dirs and databases
uv run cyber-rt doctor        # verify config and Backboard connectivity
uv run cyber-rt list-strategies
uv run cyber-rt run --target-id https://agent.example.com/chat \
    --strategies prompt_injection,tool_misuse,sensitive_data_exposure
uv run cyber-rt server --port 8001
uv run --extra dev pytest
```

## Strategies

| Strategy | ASI |
|---|---|
| `prompt_injection`, `indirect_injection`, `jailbreak`, `instruction_hierarchy` | ASI01 |
| `tool_misuse` | ASI02 |
| `privilege_escalation`, `authorization_boundary` | ASI03 |
| `sensitive_data_exposure` | ASI04 |
| `memory_poisoning`, `context_isolation` | ASI05 |
| `agent_handoff_corruption` | ASI06 |
| `retrieval_poisoning` | ASI08 |
| `workflow_manipulation` | ASI09 |

The taxonomy in `configs/asi_taxonomy.yaml` resolves `strategy + component` to an ASI class and ATLAS technique (first match wins, `*` is a wildcard).

## Configuration

See `.env.example` for every variable. The important ones: `BACKBOARD_API_KEY`, `BACKBOARD_LLM_PROVIDER`, `BACKBOARD_MODEL_NAME`, `API_SECRET_KEY`, `ALLOWED_TARGETS`, `REQUIRE_TARGET_ALLOWLIST`.
