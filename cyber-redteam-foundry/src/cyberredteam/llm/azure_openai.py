"""LLM client wrapper with observability.

Provider-neutral wrapper around any LangChain ``BaseChatModel`` (now
``ChatBedrockConverse`` for Claude on AWS Bedrock).  Every LLM call logs:
agent name, model, latency, token usage, input/output hashes.  Logs are
stored in SQLite via the artifact store.
"""

import hashlib
import time
from typing import Any, Dict, Optional, Type

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel

from cyberredteam.logging import setup_logging

logger = setup_logging()


class ObservableLLM:
    """Wrapper around a LangChain chat model that logs every call.

    Args:
        llm: Underlying ``BaseChatModel`` (e.g. ``ChatBedrockConverse``).
        agent_name: Name of the calling agent (for observability).
        deployment: Bedrock model / inference-profile ID (for observability).
        store: Optional ``SQLiteStore`` for persisting call logs.
    """

    def __init__(
        self,
        llm: BaseChatModel,
        agent_name: str = "unknown",
        deployment: str = "unknown",
        store: Any = None,
    ):
        self.llm = llm
        self.agent_name = agent_name
        self.deployment = deployment
        self.store = store

    # ─── Structured output ───────────────────────────────────────

    def invoke_structured(
        self,
        system_prompt: str,
        user_message: str,
        output_schema: Type[BaseModel],
    ) -> BaseModel:
        """Call the LLM with structured output.

        Uses ``llm.with_structured_output()`` for guaranteed JSON.

        Args:
            system_prompt: System-level instructions.
            user_message: User-level input.
            output_schema: Pydantic model to parse into.

        Returns:
            Parsed Pydantic model instance.
        """
        structured_llm = self.llm.with_structured_output(output_schema)

        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_message),
        ]

        start = time.time()
        result = structured_llm.invoke(messages)
        latency = time.time() - start

        # Observability
        self._log_call(
            input_text=f"{system_prompt}\n---\n{user_message}",
            output_text=result.model_dump_json() if result else "",
            latency=latency,
            token_usage=self._extract_tokens(result),
        )

        return result

    # ─── Free-form invoke (for reporter narrative) ───────────────

    def invoke_text(
        self,
        system_prompt: str,
        user_message: str,
    ) -> str:
        """Call the LLM for free-form text output.

        Args:
            system_prompt: System instructions.
            user_message: User input.

        Returns:
            Raw text response.
        """
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_message),
        ]

        start = time.time()
        result = self.llm.invoke(messages)
        latency = time.time() - start

        output = result.content if hasattr(result, "content") else str(result)

        self._log_call(
            input_text=f"{system_prompt}\n---\n{user_message}",
            output_text=output,
            latency=latency,
            token_usage=self._extract_tokens(result),
        )

        return output

    # ─── Observability ───────────────────────────────────────────

    def _log_call(
        self,
        input_text: str,
        output_text: str,
        latency: float,
        token_usage: Optional[Dict[str, int]] = None,
    ) -> None:
        """Log LLM call details."""
        input_hash = hashlib.sha256(input_text.encode()).hexdigest()[:16]
        output_hash = hashlib.sha256(output_text.encode()).hexdigest()[:16]

        logger.info(
            f"[LLM] agent={self.agent_name} "
            f"deployment={self.deployment} "
            f"latency={latency:.2f}s "
            f"input_hash={input_hash} "
            f"output_hash={output_hash}"
        )

        if token_usage:
            logger.info(
                f"[LLM] tokens: prompt={token_usage.get('prompt_tokens', '?')} "
                f"completion={token_usage.get('completion_tokens', '?')} "
                f"total={token_usage.get('total_tokens', '?')}"
            )

        # Persist to SQLite if store available
        if self.store and hasattr(self.store, "save_llm_call"):
            try:
                self.store.save_llm_call(
                    agent_name=self.agent_name,
                    deployment=self.deployment,
                    latency=latency,
                    input_hash=input_hash,
                    output_hash=output_hash,
                    prompt_tokens=token_usage.get("prompt_tokens", 0) if token_usage else 0,
                    completion_tokens=token_usage.get("completion_tokens", 0) if token_usage else 0,
                )
            except Exception as exc:
                logger.debug(f"Failed to persist LLM call log: {exc}")

    @staticmethod
    def _extract_tokens(result: Any) -> Optional[Dict[str, int]]:
        """Try to extract token usage from response.

        Handles LangChain's normalized ``usage_metadata`` (used by
        ``ChatBedrockConverse``: ``input_tokens``/``output_tokens``) and
        falls back to the older OpenAI-shaped ``response_metadata``.
        Structured-output calls return a Pydantic model with no usage
        metadata, in which case this returns ``None``.
        """
        # LangChain normalized usage (Bedrock Converse, current models)
        usage_meta = getattr(result, "usage_metadata", None)
        if usage_meta:
            input_tokens = usage_meta.get("input_tokens", 0)
            output_tokens = usage_meta.get("output_tokens", 0)
            return {
                "prompt_tokens": input_tokens,
                "completion_tokens": output_tokens,
                "total_tokens": usage_meta.get(
                    "total_tokens", input_tokens + output_tokens
                ),
            }

        # Fallback: provider-specific response_metadata shapes
        if hasattr(result, "response_metadata"):
            meta = result.response_metadata or {}
            usage = meta.get("token_usage") or meta.get("usage") or {}
            if usage:
                # Bedrock Converse uses inputTokens/outputTokens; OpenAI uses
                # prompt_tokens/completion_tokens.
                prompt = usage.get("prompt_tokens", usage.get("inputTokens", 0))
                completion = usage.get(
                    "completion_tokens", usage.get("outputTokens", 0)
                )
                return {
                    "prompt_tokens": prompt,
                    "completion_tokens": completion,
                    "total_tokens": usage.get(
                        "total_tokens", usage.get("totalTokens", prompt + completion)
                    ),
                }
        return None
