"""Target adapter for executing attack cases against different deployment types."""

import json
import hashlib
import time
import requests
from typing import Any, Dict, Optional, Tuple

from cyberredteam.logging import setup_logging
from cyberredteam.logging import log_event

logger = setup_logging()

_PROMPT_PLACEHOLDER = '"{{PROMPT}}"'


def _render_request_body(template: str, prompt: str) -> dict:
    """Substitute the ``{{PROMPT}}`` placeholder into a JSON request template.

    The placeholder must appear in a quoted string position (``"{{PROMPT}}"``).
    Swapping in ``json.dumps(prompt)`` — which itself is a quoted, escaped JSON
    string literal — guarantees the result stays valid JSON regardless of
    quotes/newlines/unicode in the prompt.
    """
    rendered = template.replace(_PROMPT_PLACEHOLDER, json.dumps(prompt))
    return json.loads(rendered)


def _extract_by_path(data: Any, path: str) -> Optional[str]:
    """Walk a dot-path (e.g. ``choices.0.message.content``) through parsed JSON.

    Numeric segments are treated as list indices. Returns None if the path
    doesn't resolve, so callers can fall back to the default heuristic.
    """
    current = data
    for segment in path.split("."):
        try:
            if isinstance(current, list):
                current = current[int(segment)]
            elif isinstance(current, dict):
                current = current[segment]
            else:
                return None
        except (KeyError, IndexError, ValueError, TypeError):
            return None
    return current if isinstance(current, str) else None


class TargetAdapter:
    """Abstract adapter for different target types."""

    def execute_attack(self, payload: str, label: str = "") -> Tuple[str, Optional[str]]:
        """Send an adversarial payload to the target.

        Args:
            payload: The exact prompt/input to send to the target agent.
            label: Optional technique/category label, used only for logging.

        Returns:
            Tuple of (response_text, canary_token).
            canary_token is non-None when the adapter injected a canary into the
            target's context — the evaluator checks if it was exfiltrated.
        """
        raise NotImplementedError

    def reset_context(self) -> None:
        """Reset target context if supported."""
        pass


class HttpTargetAdapter(TargetAdapter):
    """Adapter that sends adversarial prompts to any HTTP agent endpoint.

    This is the primary adapter for attacking real, independently-deployed
    open-source agents (e.g. LangChain ReAct agents, AutoGen agents, etc.)
    """

    def __init__(
        self,
        endpoint: str,
        api_key: Optional[str] = None,
        timeout: int = 60,
        headers: Optional[Dict[str, str]] = None,
        request_template: Optional[str] = None,
        response_path: Optional[str] = None,
    ):
        """Initialize HTTP adapter.

        Args:
            endpoint: Full URL to the agent's chat endpoint (e.g. http://localhost:9000/chat).
            api_key: Optional API key, sent as ``Authorization: Bearer {api_key}``.
            timeout: Request timeout in seconds.
            headers: Optional extra HTTP headers, merged on top of the default
                Content-Type/Bearer headers — covers custom auth schemes,
                API-key headers, cookies, etc. for arbitrary third-party agents.
            request_template: Optional JSON string with a ``"{{PROMPT}}"``
                placeholder describing the target's request schema (e.g.
                ``{"messages": [{"role": "user", "content": "{{PROMPT}}"}]}``).
                Defaults to ``{"message": prompt}`` when omitted.
            response_path: Optional dot-path (e.g. ``choices.0.message.content``)
                into the JSON response. Falls back to key-guessing when omitted
                or unresolvable.
        """
        import os
        is_docker = os.path.exists("/.dockerenv") or os.environ.get("RUNNING_IN_DOCKER") == "true"
        if is_docker:
            for host in ["localhost:9000", "127.0.0.1:9000"]:
                if host in endpoint:
                    endpoint = endpoint.replace(host, "host.docker.internal:9000")

        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.extra_headers = headers or {}
        self.request_template = request_template
        self.response_path = response_path
        self.target_id = endpoint  # For logging
        self.last_observation: Dict[str, Any] = {
            "stage": "target_request",
            "status": "not_started",
            "endpoint": self.endpoint,
        }

        logger.info(f"HttpTargetAdapter initialized → {self.endpoint}")

    def _build_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.extra_headers)
        return headers

    def execute_attack(self, payload: str, label: str = "") -> Tuple[str, Optional[str]]:
        """Send adversarial prompt to the HTTP agent endpoint."""
        prompt = payload
        logger.info(
            f"HTTP target '{self.endpoint}' executing attack type "
            f"'{label}': {prompt[:60]}..."
        )

        if self.request_template:
            try:
                request_body = _render_request_body(self.request_template, prompt)
            except (json.JSONDecodeError, TypeError) as e:
                logger.error(f"Invalid request_template, falling back to default: {e}")
                request_body = {"message": prompt}
        else:
            request_body = {"message": prompt}

        started = time.perf_counter()
        request_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        try:
            resp = requests.post(
                self.endpoint,
                json=request_body,
                headers=self._build_headers(),
                timeout=self.timeout,
            )
            latency_ms = round((time.perf_counter() - started) * 1000, 2)
            self.last_observation = {
                "stage": "target_request",
                "status": "response",
                "endpoint": self.endpoint,
                "http_status": resp.status_code,
                "latency_ms": latency_ms,
                "request_hash": request_hash,
                "response_hash": hashlib.sha256(resp.content).hexdigest()[:16],
                "response_bytes": len(resp.content),
            }
            log_event(logger, "target_response", **self.last_observation)
            resp.raise_for_status()
            data = resp.json()

            response_text = None
            if self.response_path:
                response_text = _extract_by_path(data, self.response_path)
                if response_text is None:
                    logger.warning(
                        f"response_path '{self.response_path}' did not resolve — "
                        "falling back to default key-guessing"
                    )
            if response_text is None:
                # Support various common response schemas
                response_text = (
                    (data.get("response") if isinstance(data, dict) else None)
                    or (data.get("output") if isinstance(data, dict) else None)
                    or (data.get("content") if isinstance(data, dict) else None)
                    or (data.get("text") if isinstance(data, dict) else None)
                    or str(data)
                )
            # HTTP targets don't support canary injection
            return response_text, None

        except requests.exceptions.Timeout:
            self.last_observation = {
                "stage": "target_request", "status": "timeout", "endpoint": self.endpoint,
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "request_hash": request_hash, "error_type": "timeout",
            }
            log_event(logger, "target_error", **self.last_observation)
            logger.warning(f"HTTP target timed out after {self.timeout}s")
            return "(target agent timed out)", None
        except requests.exceptions.ConnectionError:
            self.last_observation = {
                "stage": "target_request", "status": "unreachable", "endpoint": self.endpoint,
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "request_hash": request_hash, "error_type": "connection_error",
            }
            log_event(logger, "target_error", **self.last_observation)
            logger.error(f"Cannot connect to target at {self.endpoint}")
            return "(target agent unreachable)", None
        except Exception as e:
            response_obj = locals().get("resp")
            self.last_observation = {
                "stage": "target_request", "status": "error", "endpoint": self.endpoint,
                "latency_ms": round((time.perf_counter() - started) * 1000, 2),
                "request_hash": request_hash, "error_type": type(e).__name__,
                "error": str(e),
            }
            if response_obj is not None:
                self.last_observation["http_status"] = response_obj.status_code
                self.last_observation["response_hash"] = hashlib.sha256(response_obj.content).hexdigest()[:16]
                self.last_observation["response_bytes"] = len(response_obj.content)
            log_event(logger, "target_error", **self.last_observation)
            logger.error(f"HTTP target error: {e}")
            return f"(target error: {e})", None
