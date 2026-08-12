"""Backboard LLM transport used by all production Canary agents.

Backboard exposes a provider-neutral HTTP API. This adapter preserves the
small chain/observability contract used by the existing Strategist, Attacker,
Evaluator, and Reporter agents without coupling Canary to a provider SDK.
"""

import hashlib
import json
import time
from typing import Any, Optional, Type

import httpx
from pydantic import BaseModel

from cyberredteam.logging import setup_logging
from cyberredteam.settings import get_settings

logger = setup_logging()


class _BackboardChain:
    def __init__(self, client: "BackboardObservableLLM", system_prompt: str, schema: Optional[Type[BaseModel]] = None):
        self.client = client
        self.system_prompt = system_prompt
        self.schema = schema

    def invoke(self, values: dict[str, str]) -> Any:
        return self.client._complete(self.system_prompt, values.get("user_message", ""), self.schema)


class BackboardObservableLLM:
    """Synchronous Backboard client with typed JSON output and call logging."""

    def __init__(self, api_key: str, agent_name: str, model: str, provider: str, store: Any = None, base_url: str = "https://app.backboard.io/api"):
        self.api_key = api_key
        self.agent_name = agent_name
        self.deployment = model
        self.provider = provider
        self.store = store
        self.base_url = base_url.rstrip("/")
        self.last_status_code: Optional[int] = None
        self.last_retry_count = 0
        self.last_usage: dict[str, int] = {}
        self.last_output = ""
        self.last_error: Optional[str] = None

    def build_structured_chain(self, system_prompt: str, output_schema: Type[BaseModel]) -> _BackboardChain:
        return _BackboardChain(self, system_prompt, output_schema)

    def build_text_chain(self, system_prompt: str) -> _BackboardChain:
        return _BackboardChain(self, system_prompt)

    def invoke_chain(self, chain: _BackboardChain, user_message: str, system_context: str = "") -> Any:
        start = time.time()
        input_text = f"{system_context}\n---\n{user_message}"
        self.last_output = ""
        self.last_error = None
        self.last_status_code = None
        self.last_retry_count = 0
        self.last_usage = {}
        try:
            result = chain.invoke({"user_message": user_message})
            output_text = self.last_output or (result.model_dump_json() if hasattr(result, "model_dump_json") else str(result))
            if not self.last_usage.get("prompt_tokens"):
                self.last_usage["prompt_tokens"] = max(1, len(input_text) // 4)
            if not self.last_usage.get("completion_tokens"):
                self.last_usage["completion_tokens"] = max(1, len(output_text) // 4)
            self.last_usage["total_tokens"] = self.last_usage["prompt_tokens"] + self.last_usage["completion_tokens"]
            return result
        except Exception as exc:
            self.last_error = str(exc)
            raise
        finally:
            if not self.last_usage:
                self.last_usage = {"prompt_tokens": max(1, len(input_text) // 4), "completion_tokens": max(1, len(self.last_output) // 4), "total_tokens": max(1, (len(input_text) + len(self.last_output)) // 4)}
            self._log_call(input_text, self.last_output, time.time() - start)

    def invoke_structured(self, system_prompt: str, user_message: str, output_schema: Type[BaseModel]) -> BaseModel:
        return self.invoke_chain(self.build_structured_chain(system_prompt, output_schema), user_message, system_context=system_prompt)

    def invoke_text(self, system_prompt: str, user_message: str) -> str:
        return self.invoke_chain(self.build_text_chain(system_prompt), user_message, system_context=system_prompt)

    def _complete(self, system_prompt: str, user_message: str, schema: Optional[Type[BaseModel]]) -> Any:
        settings = get_settings()
        payload = {
            "content": user_message,
            "system_prompt": system_prompt,
            "llm_provider": self.provider,
            "model_name": self.deployment,
            "stream": False,
        }
        if schema is not None:
            payload["json_output"] = True

        last_error: Optional[Exception] = None
        for attempt in range(max(1, settings.max_retries)):
            try:
                response = httpx.post(
                    f"{self.base_url}/threads/messages",
                    headers={"X-API-Key": self.api_key, "Content-Type": "application/json"},
                    json=payload,
                    timeout=settings.timeout_seconds,
                )
                self.last_status_code = response.status_code
                self.last_retry_count = attempt
                response.raise_for_status()
                body = response.json()
                usage = body.get("usage") or {}
                self.last_usage = {
                    "prompt_tokens": int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0),
                    "completion_tokens": int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0),
                    "total_tokens": int(usage.get("total_tokens", 0) or 0),
                }
                content = body.get("content", "")
                if not content:
                    raise RuntimeError(f"Backboard returned no content (status={body.get('status')})")
                self.last_output = content
                if schema is None:
                    return content
                cleaned = content.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
                return schema.model_validate(json.loads(cleaned))
            except Exception as exc:
                last_error = exc
                if attempt + 1 < max(1, settings.max_retries):
                    time.sleep(min(2 ** attempt, 4))
        raise RuntimeError(f"Backboard request failed after retries: {last_error}") from last_error

    def _log_call(self, input_text: str, output_text: str, latency: float) -> None:
        input_hash = hashlib.sha256(input_text.encode()).hexdigest()[:16]
        output_hash = hashlib.sha256(output_text.encode()).hexdigest()[:16]
        logger.info(f"[LLM] agent={self.agent_name} provider=backboard/{self.provider} model={self.deployment} status={self.last_status_code} retries={self.last_retry_count} latency={latency:.2f}s input_hash={input_hash} output_hash={output_hash} prompt_tokens={self.last_usage.get('prompt_tokens', 0)} completion_tokens={self.last_usage.get('completion_tokens', 0)}")
        if self.store and hasattr(self.store, "save_llm_call"):
            self.store.save_llm_call(agent_name=self.agent_name, deployment=f"backboard/{self.provider}/{self.deployment}", latency=latency, input_hash=input_hash, output_hash=output_hash, prompt_tokens=self.last_usage.get("prompt_tokens", 0), completion_tokens=self.last_usage.get("completion_tokens", 0), total_tokens=self.last_usage.get("total_tokens", 0), input_text=input_text, output_text=output_text, status_code=self.last_status_code, retry_count=self.last_retry_count, error=self.last_error)
