"""Provider-compatible LLM client with LCEL chains and observability.

Wraps any LangChain ``BaseChatModel`` (currently NVIDIA ``ChatOpenAI``) and
builds LCEL chains for every invocation:

  structured:  ChatPromptTemplate | llm.with_structured_output(schema)
  text:        ChatPromptTemplate | llm | StrOutputParser()

Every call logs: agent name, model, latency, input/output hashes to the
logger and optionally to SQLite via the artifact store.
"""

import hashlib
import time
from typing import Any, Dict, Optional, Type

import botocore.exceptions
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import SystemMessage
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, HumanMessagePromptTemplate, PromptTemplate
from langchain_core.runnables import Runnable
from pydantic import BaseModel

from cyberredteam.logging import log_event, setup_logging
from cyberredteam.settings import get_settings

logger = setup_logging()


def _retryable_errors() -> tuple[type[BaseException], ...]:
    """Return provider errors that are safe to retry for NVIDIA/OpenAI."""
    errors: list[type[BaseException]] = [botocore.exceptions.ClientError]
    try:
        import openai
        errors.append(openai.APIError)
    except ImportError:  # pragma: no cover - dependency exists in production
        pass
    return tuple(errors)


class ObservableLLM:
    """Chat model wrapper that builds LCEL chains and logs every call.

    Args:
        llm: Underlying ``BaseChatModel`` (e.g. ``ChatOpenAI``).
        agent_name: Name of the calling agent (for observability).
        deployment: Provider model ID (for observability).
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

    # ─── Chain builders ──────────────────────────────────────────

    def _build_prompt(self, system_prompt: str) -> ChatPromptTemplate:
        """Build a ChatPromptTemplate that treats the system prompt as a literal.

        Passing a pre-built ``SystemMessage`` (not a tuple) prevents
        LangChain from parsing ``{...}`` placeholders inside the loaded
        ``.md`` prompt files, which often contain JSON examples with braces.
        """
        return ChatPromptTemplate.from_messages([
            SystemMessage(content=system_prompt),
            HumanMessagePromptTemplate(
                prompt=PromptTemplate(
                    template="{user_message}",
                    input_variables=["user_message"],
                )
            ),
        ])

    def build_structured_chain(
        self, system_prompt: str, output_schema: Type[BaseModel]
    ) -> Runnable:
        """Build a reusable LCEL chain for structured Pydantic output.

        Chain: ``ChatPromptTemplate | llm.with_structured_output(schema)``

        Args:
            system_prompt: System-level instructions (baked as a literal ``SystemMessage``).
            output_schema: Pydantic model the chain must produce.

        Returns:
            A ``Runnable`` accepting ``{"user_message": str}`` and returning
            an instance of ``output_schema``.
        """
        prompt = self._build_prompt(system_prompt)
        # Preserve the raw provider message so token usage metadata survives
        # structured-output parsing.
        chain = prompt | self.llm.with_structured_output(output_schema, include_raw=True)
        return chain.with_retry(
            retry_if_exception_type=_retryable_errors(),
            wait_exponential_jitter=True,
            stop_after_attempt=get_settings().max_retries,
        )

    def build_text_chain(self, system_prompt: str) -> Runnable:
        """Build a reusable LCEL chain for plain-text output.

        Chain: ``ChatPromptTemplate | llm | StrOutputParser()``

        Args:
            system_prompt: System-level instructions (baked as a literal ``SystemMessage``).

        Returns:
            A ``Runnable`` accepting ``{"user_message": str}`` and returning
            a ``str``.
        """
        prompt = self._build_prompt(system_prompt)
        chain = prompt | self.llm | StrOutputParser()
        return chain.with_retry(
            retry_if_exception_type=_retryable_errors(),
            wait_exponential_jitter=True,
            stop_after_attempt=get_settings().max_retries,
        )

    # ─── Invoke with observability ────────────────────────────────

    def invoke_chain(
        self,
        chain: Runnable,
        user_message: str,
        system_context: str = "",
        run_id: Optional[str] = None,
    ) -> Any:
        """Invoke a pre-built LCEL chain with latency and hash logging.

        Args:
            chain: Built by ``build_structured_chain`` or ``build_text_chain``.
            user_message: Fills the ``{user_message}`` slot in the template.
            system_context: System prompt string used only for input-hash logging.

        Returns:
            Whatever the chain produces (Pydantic model or ``str``).
        """
        start = time.time()
        try:
            result = chain.invoke({"user_message": user_message})
        except Exception as exc:
            log_event(
                logger,
                "llm_error",
                agent=self.agent_name,
                deployment=self.deployment,
                error_type=type(exc).__name__,
                error=str(exc),
            )
            raise
        latency = time.time() - start

        token_source = result.get("raw") if isinstance(result, dict) else result
        token_usage = self._extract_tokens(token_source)
        if isinstance(result, dict) and "parsed" in result:
            if result.get("parsing_error"):
                raise result["parsing_error"]
            result = result["parsed"]

        output_text = (
            result.model_dump_json()
            if hasattr(result, "model_dump_json")
            else str(result)
        )
        self._log_call(
            input_text=f"{system_context}\n---\n{user_message}",
            output_text=output_text,
            latency=latency,
            token_usage=token_usage,
            run_id=run_id,
        )
        return result

    # ─── Convenience wrappers (build + invoke in one call) ───────

    def invoke_structured(
        self,
        system_prompt: str,
        user_message: str,
        output_schema: Type[BaseModel],
    ) -> BaseModel:
        """Build a structured-output LCEL chain and invoke it.

        Use ``build_structured_chain`` + ``invoke_chain`` instead when the same
        chain is called many times (avoids rebuilding the chain per call).
        """
        chain = self.build_structured_chain(system_prompt, output_schema)
        return self.invoke_chain(chain, user_message, system_context=system_prompt)

    def invoke_text(self, system_prompt: str, user_message: str) -> str:
        """Build a text-output LCEL chain and invoke it."""
        chain = self.build_text_chain(system_prompt)
        return self.invoke_chain(chain, user_message, system_context=system_prompt)

    # ─── Observability helpers ────────────────────────────────────

    def _log_call(
        self,
        input_text: str,
        output_text: str,
        latency: float,
        token_usage: Optional[Dict[str, int]] = None,
        run_id: Optional[str] = None,
    ) -> None:
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
                    run_id=run_id,
                )
            except Exception as exc:
                logger.debug(f"Failed to persist LLM call log: {exc}")

    @staticmethod
    def _extract_tokens(result: Any) -> Optional[Dict[str, int]]:
        """Try to extract token usage from a response object.

        Handles LangChain's ``usage_metadata`` (OpenAI-compatible responses) and the
        older ``response_metadata`` shapes.  Returns ``None`` for structured
        Pydantic outputs which carry no usage information.
        """
        usage_meta = getattr(result, "usage_metadata", None)
        if usage_meta:
            i = usage_meta.get("input_tokens", 0)
            o = usage_meta.get("output_tokens", 0)
            return {
                "prompt_tokens": i,
                "completion_tokens": o,
                "total_tokens": usage_meta.get("total_tokens", i + o),
            }

        if hasattr(result, "response_metadata"):
            meta = result.response_metadata or {}
            usage = meta.get("token_usage") or meta.get("usage") or {}
            if usage:
                p = usage.get("prompt_tokens", usage.get("inputTokens", 0))
                c = usage.get("completion_tokens", usage.get("outputTokens", 0))
                return {
                    "prompt_tokens": p,
                    "completion_tokens": c,
                    "total_tokens": usage.get("total_tokens", usage.get("totalTokens", p + c)),
                }
        return None
