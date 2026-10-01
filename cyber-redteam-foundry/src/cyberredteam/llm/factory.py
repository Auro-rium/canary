"""LLM factory — creates per-agent Backboard.io clients.

Optional per-agent ``provider``/``model`` overrides live in
``configs/models.yaml``; anything unset falls back to the ``BACKBOARD_*``
environment settings.

There is **no** mock fallback: if Backboard is not configured the factory
raises, so a misconfigured deployment fails loudly instead of fabricating
security findings.
"""

from pathlib import Path
from typing import Optional

import yaml

from cyberredteam.llm.backboard import ChatBackboard
from cyberredteam.llm.observable import ObservableLLM
from cyberredteam.logging import setup_logging

logger = setup_logging()

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


def _agent_config(agent_name: str) -> dict:
    config = _load_models_config().get(agent_name, {})
    return config if isinstance(config, dict) else {"model": str(config)}


def get_model_for_agent(agent_name: str) -> Optional[str]:
    """Model name configured for an agent, or ``None`` for the Backboard default."""
    return _agent_config(agent_name).get("model")


def get_provider_for_agent(agent_name: str) -> Optional[str]:
    """LLM provider configured for an agent, or ``None`` for the Backboard default."""
    return _agent_config(agent_name).get("provider")


def get_llm(
    model: Optional[str] = None,
    agent_name: str = "unknown",
    store: object = None,
    provider: Optional[str] = None,
) -> ObservableLLM:
    """Create an ObservableLLM backed by Backboard.io.

    Args:
        model: Backboard ``model_name``; defaults to ``BACKBOARD_MODEL_NAME``.
        agent_name: Name for logging.
        store: Optional SQLiteStore for call logging.
        provider: Backboard ``llm_provider``; defaults to ``BACKBOARD_LLM_PROVIDER``.

    Raises:
        RuntimeError: If ``BACKBOARD_API_KEY`` is not configured. We never
        fall back to fabricated output — a security tool that invents
        findings is worse than one that fails.
    """
    from cyberredteam.settings import get_settings

    settings = get_settings()

    if not settings.backboard_api_key:
        raise RuntimeError(
            "Backboard is not configured: BACKBOARD_API_KEY is unset. "
            "Set BACKBOARD_API_KEY before running. Refusing to fabricate LLM output."
        )

    model = model or settings.backboard_model_name
    provider = provider or settings.backboard_llm_provider
    llm = ChatBackboard(
        api_key=settings.backboard_api_key,
        base_url=settings.backboard_base_url,
        provider=provider,
        model_name=model,
        timeout=settings.backboard_timeout_seconds,
    )
    logger.info(f"Created Backboard client for {agent_name} ({provider}/{model})")

    return ObservableLLM(
        llm=llm,
        agent_name=agent_name,
        deployment=f"{provider}/{model}",
        store=store,
    )


def get_llm_for_agent(
    agent_name: str,
    store: object = None,
) -> ObservableLLM:
    """Create an ObservableLLM using the configured provider/model for an agent."""
    return get_llm(
        get_model_for_agent(agent_name),
        agent_name=agent_name,
        store=store,
        provider=get_provider_for_agent(agent_name),
    )


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
