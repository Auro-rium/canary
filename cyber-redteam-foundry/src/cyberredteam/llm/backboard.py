"""Backboard.io chat model for LangChain.

Backboard exposes one endpoint per turn, ``POST {base_url}/threads/messages``,
authenticated with an ``X-API-Key`` header. Provider and model are chosen per
request (``llm_provider`` / ``model_name``), so any provider Backboard routes
to can power any agent role.

Every call is stateless: no ``thread_id`` is sent, so Backboard opens a fresh
thread and the system prompt is passed on every call.

Structured output is prompt-based: the system message carries the Pydantic JSON
schema, the reply is parsed with :func:`extract_json` and validated. A validation
failure triggers exactly ONE repair re-ask (with the error); a second failure
fails closed.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Type

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda
from pydantic import BaseModel


class BackboardError(RuntimeError):
    """Non-retryable Backboard failure (bad key, invalid request, failed run)."""


class BackboardRetryableError(BackboardError):
    """Transient Backboard failure (rate limit or 5xx) that is safe to retry."""


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def extract_json(text: str) -> Any:
    """Parse the JSON object in ``text``, tolerating code fences and prose."""
    cleaned = _FENCE.sub("", text.strip())
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(cleaned[start : end + 1])


def _content_text(content: Any) -> str:
    """Flatten Backboard content, which may be a string or a list of blocks."""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        return " ".join(
            block.get("text", "") if isinstance(block, dict) else str(block)
            for block in content
            if not (isinstance(block, dict) and block.get("type") == "reasoning")
        ).strip()
    return "" if content is None else str(content).strip()


class ChatBackboard(BaseChatModel):
    """LangChain chat model backed by the Backboard.io messages API."""

    api_key: str
    base_url: str = "https://app.backboard.io/api"
    provider: str = "openai"
    model_name: str = "gpt-4o"
    temperature: Optional[float] = None
    timeout: float = 60.0
    # Injectable ``httpx.BaseTransport`` (tests use ``httpx.MockTransport``).
    transport: Any = None

    @property
    def _llm_type(self) -> str:
        return "backboard"

    @property
    def _identifying_params(self) -> Dict[str, Any]:
        return {"provider": self.provider, "model_name": self.model_name}

    # ─── Transport ────────────────────────────────────────────────

    def _post_message(
        self, messages: List[BaseMessage], json_output: bool = False
    ) -> Dict[str, Any]:
        system = "\n\n".join(str(m.content) for m in messages if isinstance(m, SystemMessage))
        content = "\n\n".join(str(m.content) for m in messages if not isinstance(m, SystemMessage))
        payload: Dict[str, Any] = {
            "content": content,
            "llm_provider": self.provider,
            "model_name": self.model_name,
            "stream": False,
            "memory": "off",
        }
        if system:
            payload["system_prompt"] = system
        if json_output:
            payload["json_output"] = True
        if self.temperature is not None:
            payload["temperature"] = self.temperature

        try:
            with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
                response = client.post(
                    f"{self.base_url.rstrip('/')}/threads/messages",
                    headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
                    json=payload,
                )
        except httpx.TransportError as exc:  # timeouts, connection resets
            raise BackboardRetryableError(f"Backboard transport error: {exc}") from exc
        if response.status_code == 429 or response.status_code >= 500:
            raise BackboardRetryableError(f"Backboard returned HTTP {response.status_code}")
        if response.status_code >= 400:
            raise BackboardError(
                f"Backboard returned HTTP {response.status_code}: {response.text[:300]}"
            )
        body = response.json()
        if not isinstance(body, dict):
            raise BackboardError("Backboard returned an invalid response body")
        if body.get("status") in ("FAILED", "CANCELLED"):
            raise BackboardError(f"Backboard run {str(body['status']).lower()}")
        return body

    @staticmethod
    def _to_ai_message(body: Dict[str, Any]) -> AIMessage:
        text = _content_text(body.get("content"))
        if not text:
            raise BackboardRetryableError("Backboard returned an empty response")
        usage = None
        if body.get("total_tokens") is not None:
            i, o = body.get("input_tokens") or 0, body.get("output_tokens") or 0
            usage = {
                "input_tokens": i,
                "output_tokens": o,
                "total_tokens": body["total_tokens"],
            }
        return AIMessage(content=text, usage_metadata=usage)

    def _generate(
        self,
        messages: List[BaseMessage],
        stop: Optional[List[str]] = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        message = self._to_ai_message(self._post_message(messages))
        return ChatResult(generations=[ChatGeneration(message=message)])

    # ─── Structured output ────────────────────────────────────────

    def with_structured_output(
        self, schema: Type[BaseModel], *, include_raw: bool = False, **kwargs: Any
    ) -> Runnable:
        """Return a runnable producing ``schema`` instances via Backboard JSON mode.

        One repair re-ask is allowed on a parse/validation error; after that the
        failure is surfaced (fail closed). With ``include_raw`` the result is
        ``{"raw", "parsed", "parsing_error"}`` so token usage survives parsing.
        """
        instruction = SystemMessage(
            content=(
                "Respond with a single JSON object and nothing else. It must validate "
                "against this JSON schema:\n" + json.dumps(schema.model_json_schema())
            )
        )

        def _attempt(messages: List[BaseMessage]) -> tuple[AIMessage, Any, Optional[Exception]]:
            raw = self._to_ai_message(self._post_message(messages, json_output=True))
            try:
                return raw, schema.model_validate(extract_json(str(raw.content))), None
            except ValueError as exc:  # JSONDecodeError and ValidationError
                return raw, None, exc

        def _run(prompt_value: Any) -> Any:
            messages = (
                prompt_value.to_messages()
                if hasattr(prompt_value, "to_messages")
                else [HumanMessage(content=str(prompt_value))]
            )
            base = [instruction, *messages]
            raw, parsed, error = _attempt(base)
            if error is not None:
                repair = HumanMessage(
                    content=(
                        "Your previous reply was invalid:\n"
                        f"{str(error)[:1500]}\n\n"
                        "Previous reply:\n"
                        f"{str(raw.content)[:3000]}\n\n"
                        "Reply again with ONLY a corrected JSON object that validates "
                        "against the schema."
                    )
                )
                raw2, parsed, error = _attempt([*base, repair])
                raw = _merge_usage(raw, raw2)
            if include_raw:
                return {"raw": raw, "parsed": parsed, "parsing_error": error}
            if error is not None:
                raise error
            return parsed

        return RunnableLambda(_run)


def _merge_usage(first: AIMessage, second: AIMessage) -> AIMessage:
    """Return ``second`` carrying the summed token usage of both calls."""
    a, b = first.usage_metadata, second.usage_metadata
    if a and b:
        second.usage_metadata = {
            "input_tokens": a["input_tokens"] + b["input_tokens"],
            "output_tokens": a["output_tokens"] + b["output_tokens"],
            "total_tokens": a["total_tokens"] + b["total_tokens"],
        }
    return second
