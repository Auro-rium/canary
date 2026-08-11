"""HTTP target adapter for executing attacks against owned AI agents.

Canary never executes an in-process or model-backed victim. The target is
always an independently deployed HTTP(S) agent so the result reflects the
behavior that will actually ship.
"""

import json
import hashlib
import time
from typing import Any, Dict, Optional, Tuple

import requests

from cyberredteam.logging import setup_logging
from cyberredteam.security.target import TargetValidationError, validate_target_url

logger = setup_logging()
_PROMPT_PLACEHOLDER = '"{{PROMPT}}"'


def _render_request_body(template: str, prompt: str) -> dict:
    rendered = template.replace(_PROMPT_PLACEHOLDER, json.dumps(prompt))
    return json.loads(rendered)


def _extract_by_path(data: Any, path: str) -> Optional[str]:
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
    """Adapter contract for independently deployed HTTP targets."""

    def execute_attack(self, payload: str, label: str = "") -> Tuple[str, Optional[str]]:
        raise NotImplementedError

    def reset_context(self) -> None:
        """Reset target context if the remote agent exposes that capability."""


class HttpTargetAdapter(TargetAdapter):
    """Send adversarial prompts to a real HTTP(S) AI-agent endpoint."""

    def __init__(
        self,
        endpoint: str,
        api_key: Optional[str] = None,
        timeout: int = 60,
        headers: Optional[Dict[str, str]] = None,
        request_template: Optional[str] = None,
        response_path: Optional[str] = None,
        allow_private_targets: bool = False,
    ):
        try:
            validated = validate_target_url(endpoint)
        except TargetValidationError as exc:
            if not allow_private_targets:
                raise ValueError(str(exc)) from exc
            endpoint = endpoint.strip()
        else:
            endpoint = validated.url

        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.extra_headers = headers or {}
        self.request_template = request_template
        self.response_path = response_path
        self.allow_private_targets = allow_private_targets
        self.target_id = self.endpoint
        self.last_error: Optional[str] = None
        self.last_status_code: Optional[int] = None
        self.last_latency_ms: Optional[float] = None
        self.last_request_hash: Optional[str] = None
        self.last_response_hash: Optional[str] = None
        logger.info("HttpTargetAdapter initialized → %s", self.endpoint)

    def _build_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        headers.update(self.extra_headers)
        return headers

    def execute_attack(self, payload: str, label: str = "") -> Tuple[str, Optional[str]]:
        self.last_error = None
        self.last_status_code = None
        self.last_latency_ms = None
        self.last_request_hash = None
        self.last_response_hash = None
        logger.info(
            "HTTP target '%s' executing attack type '%s': %s...",
            self.endpoint, label, payload[:60],
        )

        if self.request_template:
            try:
                request_body = _render_request_body(self.request_template, payload)
            except (json.JSONDecodeError, TypeError) as exc:
                self.last_error = f"invalid request template: {exc}"
                return "(target request template invalid)", None
        else:
            request_body = {"message": payload}
        request_bytes = json.dumps(request_body, sort_keys=True, separators=(",", ":")).encode()
        self.last_request_hash = hashlib.sha256(request_bytes).hexdigest()[:16]
        started = time.perf_counter()

        try:
            session = requests.Session()
            session.trust_env = False
            response = session.post(
                self.endpoint,
                json=request_body,
                headers=self._build_headers(),
                timeout=self.timeout,
                allow_redirects=False,
            )
            self.last_status_code = response.status_code
            self.last_latency_ms = round((time.perf_counter() - started) * 1000, 2)
            if 300 <= response.status_code < 400:
                self.last_error = f"target returned an unsafe redirect ({response.status_code})"
                return "(target redirect rejected)", None
            response.raise_for_status()
            data = response.json()
            raw_response = getattr(response, "content", b"")
            if not isinstance(raw_response, (bytes, bytearray, memoryview)):
                raw_response = json.dumps(data, sort_keys=True, default=str).encode()
            self.last_response_hash = hashlib.sha256(bytes(raw_response)).hexdigest()[:16]

            response_text = _extract_by_path(data, self.response_path) if self.response_path else None
            if self.response_path and response_text is None:
                logger.warning("response_path '%s' did not resolve; using key heuristics", self.response_path)
            if response_text is None:
                response_text = (
                    (data.get("response") if isinstance(data, dict) else None)
                    or (data.get("output") if isinstance(data, dict) else None)
                    or (data.get("content") if isinstance(data, dict) else None)
                    or (data.get("text") if isinstance(data, dict) else None)
                    or str(data)
                )
            return response_text, None

        except requests.exceptions.Timeout:
            self.last_latency_ms = round((time.perf_counter() - started) * 1000, 2)
            self.last_error = f"target agent timed out after {self.timeout}s"
            logger.warning("HTTP target timed out after %ss", self.timeout)
            return "(target agent timed out)", None
        except requests.exceptions.ConnectionError:
            self.last_latency_ms = round((time.perf_counter() - started) * 1000, 2)
            self.last_error = "target agent unreachable"
            logger.error("Cannot connect to target at %s", self.endpoint)
            return "(target agent unreachable)", None
        except Exception as exc:
            self.last_latency_ms = round((time.perf_counter() - started) * 1000, 2)
            self.last_error = f"target request failed: {exc}"
            logger.error("HTTP target error: %s", exc)
            return f"(target error: {exc})", None
