# Target Agent — Open-Source LangChain ReAct Agent

This is a **standalone, independently-deployed** LangChain ReAct agent that
serves as the "victim" for Canary Engine adversarial probes.

It is built using:
- **LangChain** (open-source agent framework)
- **LangChain ReAct Agent** (tool-calling agent pattern)
- **FastAPI** (HTTP server)
- **Azure OpenAI** (LLM backend — same deployment, but different agent identity)

## Why This Matters

Instead of attacking our own role-play prompts, the red-team engine now attacks
a real, independently-deployed agent with:
- **Real tools** (employee database, calculator, document store)
- **Real system prompt** that can be extracted
- **Real tool-calling behavior** that can be abused
- **Real multi-step reasoning** that can be hijacked

## Quick Start

```bash
# From the cyber-redteam-foundry directory:
PYTHONPATH=src .venv/bin/python -m target_agent.server

# Or with custom port:
PYTHONPATH=src .venv/bin/python -m target_agent.server --port 9000
```

Then point the red-team engine at it:
```bash
PYTHONPATH=src .venv/bin/python -m cyberredteam.cli run \
  --target-id http://localhost:9000/chat \
  --max-iterations 2
```
