"""NVIDIA NIM OpenAI-compatible transport for every Canary agent."""

import hashlib
import json
import time
from typing import Any, Optional, Type

import httpx
from pydantic import BaseModel

from cyberredteam.logging import setup_logging
from cyberredteam.settings import get_settings

logger = setup_logging()


class _Chain:
    def __init__(self, client: "NvidiaObservableLLM", system_prompt: str, schema: Optional[Type[BaseModel]] = None):
        self.client, self.system_prompt, self.schema = client, system_prompt, schema

    def invoke(self, values: dict[str, str]) -> Any:
        return self.client._complete(self.system_prompt, values.get("user_message", ""), self.schema)


class NvidiaObservableLLM:
    """Synchronous NIM client with typed JSON and SQLite telemetry."""

    def __init__(self, api_key: str, agent_name: str, model: str, store: Any = None, base_url: str = "https://integrate.api.nvidia.com/v1"):
        self.api_key, self.agent_name, self.deployment = api_key, agent_name, model
        self.store, self.base_url = store, base_url.rstrip("/")
        self.last_status_code: Optional[int] = None
        self.last_retry_count = 0
        self.last_usage: dict[str, int] = {}

    def build_structured_chain(self, system_prompt: str, output_schema: Type[BaseModel]) -> _Chain:
        return _Chain(self, system_prompt, output_schema)

    def build_text_chain(self, system_prompt: str) -> _Chain:
        return _Chain(self, system_prompt)

    def invoke_chain(self, chain: _Chain, user_message: str, system_context: str = "") -> Any:
        start = time.time()
        result = chain.invoke({"user_message": user_message})
        output = result.model_dump_json() if hasattr(result, "model_dump_json") else str(result)
        self._log_call(f"{system_context}\n---\n{user_message}", output, time.time() - start)
        return result

    def invoke_structured(self, system_prompt: str, user_message: str, output_schema: Type[BaseModel]) -> BaseModel:
        return self.invoke_chain(self.build_structured_chain(system_prompt, output_schema), user_message, system_prompt)

    def invoke_text(self, system_prompt: str, user_message: str) -> str:
        return self.invoke_chain(self.build_text_chain(system_prompt), user_message, system_prompt)

    def _complete(self, system_prompt: str, user_message: str, schema: Optional[Type[BaseModel]]) -> Any:
        settings = get_settings()
        payload: dict[str, Any] = {
            "model": self.deployment,
            "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}],
            "temperature": 0.2,
            "max_tokens": 8192,
        }
        if schema is not None:
            payload["response_format"] = {"type": "json_object"}
        last_error: Optional[Exception] = None
        for attempt in range(max(1, settings.max_retries)):
            try:
                response = httpx.post(
                    f"{self.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload,
                    timeout=settings.timeout_seconds,
                )
                self.last_status_code = getattr(response, "status_code", None)
                self.last_retry_count = attempt
                response.raise_for_status()
                body = response.json()
                usage = body.get("usage") or {}
                self.last_usage = {
                    "prompt_tokens": int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0),
                    "completion_tokens": int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0),
                    "total_tokens": int(usage.get("total_tokens", 0) or 0),
                }
                content = body["choices"][0]["message"]["content"]
                if not content:
                    raise RuntimeError("NVIDIA NIM returned empty content")
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
        raise RuntimeError(f"NVIDIA NIM request failed after retries: {last_error}") from last_error

    def _log_call(self, input_text: str, output_text: str, latency: float) -> None:
        input_hash = hashlib.sha256(input_text.encode()).hexdigest()[:16]
        output_hash = hashlib.sha256(output_text.encode()).hexdigest()[:16]
        logger.info(f"[LLM] agent={self.agent_name} provider=nvidia-nim model={self.deployment} status={self.last_status_code} retries={self.last_retry_count} latency={latency:.2f}s input_hash={input_hash} output_hash={output_hash} prompt_tokens={self.last_usage.get('prompt_tokens', 0)} completion_tokens={self.last_usage.get('completion_tokens', 0)}")
        if self.store and hasattr(self.store, "save_llm_call"):
            self.store.save_llm_call(agent_name=self.agent_name, deployment=f"nvidia-nim/{self.deployment}", latency=latency, input_hash=input_hash, output_hash=output_hash, prompt_tokens=self.last_usage.get("prompt_tokens", 0), completion_tokens=self.last_usage.get("completion_tokens", 0))
