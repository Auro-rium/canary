"""LLM factory — creates per-agent NVIDIA NIM clients.

Reads model IDs from ``configs/models.yaml`` and Backboard configuration from
environment variables. There is no mock fallback: if Backboard is not
configured the factory raises, so deployment fails loudly instead of
fabricating security findings.
"""

from pathlib import Path
from typing import Optional

import yaml

from cyberredteam.llm.nvidia import NvidiaObservableLLM
from cyberredteam.logging import setup_logging

logger = setup_logging()

# Default Backboard/OpenRouter model per agent.
# Overridable per agent via configs/models.yaml.
_DEFAULT_MODELS = {agent: {"model": "nvidia/llama-3.1-nemotron-nano-8b-v1"} for agent in ("strategist", "attacker", "evaluator", "reporter")}

_models_config: Optional[dict] = None


def _load_models_config() -> dict:
    """Load models config from yaml, falling back to defaults."""
    global _models_config
    if _models_config is not None:
        return _models_config

    config_path = Path("configs/models.yaml")
    if config_path.exists():
        with open(config_path) as f:
            _models_config = yaml.safe_load(f) or {}
        logger.info(f"Loaded model config from {config_path}")
    else:
        _models_config = {}
        logger.info("No configs/models.yaml found, using defaults")

    return _models_config


def get_model_for_agent(agent_name: str) -> str:
    """Get the Backboard model ID for a given agent.

    Args:
        agent_name: One of strategist, attacker, evaluator, reporter.

    Returns:
        Provider-specific model identifier string.
    """
    from os import getenv
    model_override = getenv("NVIDIA_MODEL", "").strip()
    if model_override:
        return model_override
    config = _load_models_config()
    agent_config = config.get(agent_name, _DEFAULT_MODELS.get(agent_name, {}))

    if isinstance(agent_config, dict):
        # Accept either "model" (preferred) or legacy "deployment" key.
        return agent_config.get("model") or agent_config.get(
            "deployment", _DEFAULT_MODELS["evaluator"]["model"]
        )
    return str(agent_config)


# Backwards-compatible alias for callers that still ask for a deployment.
def get_deployment_for_agent(agent_name: str) -> str:
    """Deprecated alias for :func:`get_model_for_agent`."""
    return get_model_for_agent(agent_name)


def get_llm(model: str, agent_name: str = "unknown", store: object = None) -> NvidiaObservableLLM:
    """Create an NVIDIA NIM client for a specific model."""
    from cyberredteam.settings import get_settings

    settings = get_settings()

    api_key = settings.nvidia_api_key
    if not api_key:
        raise RuntimeError(
            "NVIDIA NIM is not configured: NVIDIA_API_KEY is unset. "
            "Set it server-side before running. Refusing to fabricate LLM output."
        )
    return NvidiaObservableLLM(api_key=api_key, agent_name=agent_name, model=model, store=store, base_url=settings.nvidia_base_url)


def get_llm_for_agent(
    agent_name: str,
    store: object = None,
) -> NvidiaObservableLLM:
    """Create an NVIDIA NIM client using the configured model for an agent."""
    model = get_model_for_agent(agent_name)
    return get_llm(model, agent_name=agent_name, store=store)


def load_prompt(agent_name: str) -> str:
    """Load system prompt markdown file for a given agent.

    Args:
        agent_name: Name of the agent.

    Returns:
        Content of the prompt file.
    """
    prompt_path = Path("prompts") / f"{agent_name}.md"
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8")

    # Simple default prompt fallback if not found
    return f"You are the {agent_name} agent."
