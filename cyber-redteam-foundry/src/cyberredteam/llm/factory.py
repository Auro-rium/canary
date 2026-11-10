"""LLM factory — creates per-role Backboard.io clients.

Per-role ``{provider, model_name, temperature}`` live in ``configs/models.yaml``
and can be overridden with ``BACKBOARD_<ROLE>_PROVIDER`` /
``BACKBOARD_<ROLE>_MODEL_NAME``. Roles without an entry fall back to
``BACKBOARD_LLM_PROVIDER`` / ``BACKBOARD_MODEL_NAME``. The judge and evaluator
always run at temperature 0.

There is **no** mock fallback: if Backboard is not configured the factory
raises, so a misconfigured deployment fails loudly instead of fabricating
security findings.
"""

import os
from pathlib import Path
from typing import Optional

import yaml

from cyberredteam.llm.backboard import ChatBackboard
from cyberredteam.llm.observable import ObservableLLM
from cyberredteam.logging import setup_logging

logger = setup_logging()

ROLES = ("planner", "strategist", "attacker", "evaluator", "judge", "reporter")
# Roles whose output is a verdict: sampling noise is never acceptable.
DETERMINISTIC_ROLES = frozenset({"evaluator", "judge"})

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
    return config if isinstance(config, dict) else {"model_name": str(config)}


def _env_override(agent_name: str, field: str) -> Optional[str]:
    return os.environ.get(f"BACKBOARD_{agent_name.upper()}_{field}") or None


def get_role_config(agent_name: str) -> dict:
    """Resolve ``{provider, model_name, temperature}`` for a role.

    Precedence: ``BACKBOARD_<ROLE>_*`` env > ``configs/models.yaml`` >
    ``BACKBOARD_LLM_PROVIDER`` / ``BACKBOARD_MODEL_NAME`` settings.
    """
    from cyberredteam.settings import get_settings

    settings = get_settings()
    cfg = _agent_config(agent_name)
    temperature = cfg.get("temperature")
    if agent_name in DETERMINISTIC_ROLES:
        temperature = 0.0
    return {
        "provider": (
            _env_override(agent_name, "PROVIDER")
            or cfg.get("provider")
            or settings.backboard_llm_provider
        ),
        "model_name": (
            _env_override(agent_name, "MODEL_NAME")
            or cfg.get("model_name")
            or cfg.get("model")  # legacy key
            or settings.backboard_model_name
        ),
        "temperature": None if temperature is None else float(temperature),
    }


def get_model_for_agent(agent_name: str) -> str:
    """Backboard ``model_name`` configured for a role."""
    return get_role_config(agent_name)["model_name"]


def get_provider_for_agent(agent_name: str) -> str:
    """Backboard ``llm_provider`` configured for a role."""
    return get_role_config(agent_name)["provider"]


def get_llm(
    model: Optional[str] = None,
    agent_name: str = "unknown",
    store: object = None,
    provider: Optional[str] = None,
    temperature: Optional[float] = None,
) -> ObservableLLM:
    """Create an ObservableLLM backed by Backboard.io.

    Args:
        model: Backboard ``model_name``; defaults to ``BACKBOARD_MODEL_NAME``.
        agent_name: Name for logging.
        store: Optional SQLiteStore for call logging.
        provider: Backboard ``llm_provider``; defaults to ``BACKBOARD_LLM_PROVIDER``.
        temperature: Sampling temperature; forced to 0 for evaluator/judge roles.

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
    if agent_name in DETERMINISTIC_ROLES:
        temperature = 0.0
    llm = ChatBackboard(
        api_key=settings.backboard_api_key,
        base_url=settings.backboard_base_url,
        provider=provider,
        model_name=model,
        temperature=temperature,
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
    """Create an ObservableLLM using the configured provider/model for a role."""
    cfg = get_role_config(agent_name)
    return get_llm(
        cfg["model_name"],
        agent_name=agent_name,
        store=store,
        provider=cfg["provider"],
        temperature=cfg["temperature"],
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
