"""LLM factory — creates per-agent AWS Bedrock (Claude) clients.

Reads model IDs from ``configs/models.yaml`` and AWS configuration from
environment variables.  Each agent maps to a Bedrock model; high-volume
roles (attacker) can use a faster/cheaper model while judgment roles
(evaluator, reporter) use a stronger one.

Inference runs server-side through Bedrock with IAM/STS credentials
resolved by the standard boto3 credential chain (env vars, shared
config, instance/role profile).  There is **no** mock fallback: if
Bedrock is not configured the factory raises, so a misconfigured
deployment fails loudly instead of fabricating security findings.
"""

from pathlib import Path
from typing import Optional

import yaml

from cyberredteam.llm.azure_openai import ObservableLLM
from cyberredteam.logging import setup_logging

logger = setup_logging()

# Default Bedrock model IDs per agent.
#
# These are cross-region *inference profile* IDs (the ``us.`` prefix) —
# on-demand throughput for the Claude 4.x family on the Bedrock Converse
# API generally requires an inference profile rather than the bare model
# ID.  VERIFY/adjust these against the target account:
#
#     aws bedrock list-inference-profiles --region us-east-1 \
#       --query 'inferenceProfileSummaries[].inferenceProfileId'
#
# Overridable per agent via configs/models.yaml.
_DEFAULT_MODELS = {
    "strategist": {"model": "qwen.qwen3-coder-480b-a35b-v1:0"},
    "attacker": {"model": "qwen.qwen3-coder-30b-a3b-v1:0"},
    "evaluator": {"model": "qwen.qwen3-coder-480b-a35b-v1:0"},
    "defender": {"model": "qwen.qwen3-coder-480b-a35b-v1:0"},
    "reporter": {"model": "qwen.qwen3-coder-480b-a35b-v1:0"},
}

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
    """Get the Bedrock model ID for a given agent.

    Args:
        agent_name: One of strategist, attacker, evaluator, defender, reporter.

    Returns:
        Bedrock model / inference-profile ID string.
    """
    config = _load_models_config()
    agent_config = config.get(agent_name, _DEFAULT_MODELS.get(agent_name, {}))

    if isinstance(agent_config, dict):
        # Accept either "model" (preferred) or legacy "deployment" key.
        return agent_config.get("model") or agent_config.get(
            "deployment", _DEFAULT_MODELS["evaluator"]["model"]
        )
    return str(agent_config)


# Backwards-compatible alias — callers that predate the Bedrock migration
# still ask for a "deployment"; it now resolves to a Bedrock model ID.
def get_deployment_for_agent(agent_name: str) -> str:
    """Deprecated alias for :func:`get_model_for_agent`."""
    return get_model_for_agent(agent_name)


def get_llm(
    model: str,
    agent_name: str = "unknown",
    store: object = None,
) -> ObservableLLM:
    """Create an ObservableLLM for a specific Bedrock model.

    Args:
        model: Bedrock model / inference-profile ID.
        agent_name: Name for logging.
        store: Optional SQLiteStore for call logging.

    Returns:
        ``ObservableLLM`` wrapping ``ChatBedrockConverse``.

    Raises:
        RuntimeError: If AWS region is not configured.  We never fall back
            to fabricated output — a security tool that invents findings is
            worse than one that fails.
    """
    from cyberredteam.settings import get_settings

    settings = get_settings()

    if not settings.aws_region:
        raise RuntimeError(
            "AWS Bedrock is not configured: AWS_REGION is unset. "
            "Set AWS_REGION (and valid AWS credentials via the standard "
            "boto3 chain) before running. Refusing to fabricate LLM output."
        )

    try:
        from langchain_aws import ChatBedrockConverse
    except ImportError as exc:  # pragma: no cover - import guard
        raise RuntimeError(
            "langchain-aws is required for Bedrock inference. "
            "Install it with: pip install langchain-aws"
        ) from exc

    llm = ChatBedrockConverse(
        model=model,
        region_name=settings.aws_region,
        temperature=0.7,
        max_tokens=2048,
    )

    logger.info(f"Created ChatBedrockConverse for {agent_name} (model={model})")

    return ObservableLLM(
        llm=llm,
        agent_name=agent_name,
        deployment=model,
        store=store,
    )


def get_llm_for_agent(
    agent_name: str,
    store: object = None,
) -> ObservableLLM:
    """Create an ObservableLLM using the configured model for an agent.

    Args:
        agent_name: One of strategist, attacker, evaluator, defender, reporter.
        store: Optional SQLiteStore for call logging.

    Returns:
        ``ObservableLLM`` wrapping ``ChatBedrockConverse``.
    """
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
