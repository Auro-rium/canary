"""Target adapters for the legacy v1 attack flow.

The v1 graph (``attacker_branch``) is synchronous and sends one self-contained
prompt per attack. ``SessionTargetAdapter`` serves it through the v2
``SessionAdapter`` (one fresh adapter per attack), so the legacy flow gets the
same transport as v2: auth handling, response caps, ``X-Canary-Campaign``
header, no redirects, retry rules. The old ``requests``-based
``HttpTargetAdapter`` has been deleted.
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from typing import Any, Dict, Optional, Tuple

from cyberredteam.contracts import (
    RESERVED_HEADERS,
    BearerAuth,
    HeaderAuth,
    NoAuth,
    TargetConfig,
)
from cyberredteam.logging import log_event, setup_logging
from cyberredteam.transport.rate_limit import InProcessTokenBucket
from cyberredteam.transport.session_adapter import SessionAdapter, TurnResult

logger = setup_logging()

_LEGACY_PLACEHOLDER = "{{PROMPT}}"
_NAMESPACE = uuid.UUID("0c4a7e52-9d3b-5f1a-8e6c-2b7d4f9a1c30")


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
            target's context; the evaluator checks if it was exfiltrated.
        """
        raise NotImplementedError

    def reset_context(self) -> None:
        """Reset target context if supported."""
        pass


def _run_sync(coro_factory) -> Any:
    """Run a coroutine to completion from sync code, even inside a running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro_factory())
    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            box["value"] = asyncio.run(coro_factory())
        except BaseException as exc:  # re-raised in the caller
            box["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join()
    if "error" in box:
        raise box["error"]
    return box["value"]


class SessionTargetAdapter(TargetAdapter):
    """Sync ``TargetAdapter`` over a fresh v2 ``SessionAdapter`` per attack.

    The caller must already have resolved a registered, ownership-verified
    target (the v1 API does, via ``_require_verified_target``).

    Legacy arguments map as follows: ``api_key`` -> bearer auth; an
    ``Authorization: Bearer x`` header -> bearer auth; the first other custom
    header -> header auth; further headers are added as plain client headers;
    ``{{PROMPT}}`` in the request template -> ``{{MESSAGE}}``.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: Optional[str] = None,
        timeout: int = 60,
        headers: Optional[Dict[str, str]] = None,
        request_template: Optional[str] = None,
        response_path: Optional[str] = None,
        *,
        campaign_id: str = "legacy-v1",
        transport: Any = None,
        environment: str = "production",
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.target_id = endpoint  # For logging
        self.campaign_id = campaign_id
        self._transport = transport
        self._extra_headers: dict[str, str] = {}
        auth: Any = NoAuth()
        if api_key:
            auth = BearerAuth(token=api_key)
        for name, value in (headers or {}).items():
            lowered = name.lower()
            if lowered in RESERVED_HEADERS:
                continue
            if lowered == "authorization" and value.lower().startswith("bearer "):
                auth = BearerAuth(token=value[7:].strip())
            elif isinstance(auth, NoAuth) and lowered != "authorization":
                auth = HeaderAuth(header_name=name, value=value)
            else:
                self._extra_headers[name] = value
        template = request_template.replace(_LEGACY_PLACEHOLDER, "{{MESSAGE}}") if request_template else None
        self._config = TargetConfig(
            target_id=str(uuid.uuid5(_NAMESPACE, self.endpoint)),
            name="legacy-v1-target",
            endpoint=self.endpoint,
            auth=auth,
            request_template=template,
            response_path=response_path,
            session_mode="stateless_history",
            timeout_s=timeout,
            verified=True,
            environment=environment,
        )
        self.last_observation: Dict[str, Any] = {
            "stage": "target_request",
            "status": "not_started",
            "endpoint": self.endpoint,
        }
        logger.info(f"SessionTargetAdapter initialized → {self.endpoint}")

    async def _send(self, payload: str) -> TurnResult:
        adapter = SessionAdapter(
            self._config,
            campaign_id=self.campaign_id,
            rate_limiter=InProcessTokenBucket(1.0),
            transport=self._transport,
        )
        try:
            adapter._client.headers.update(self._extra_headers)
            return await adapter.send(payload)
        finally:
            await adapter.aclose()

    def execute_attack(self, payload: str, label: str = "") -> Tuple[str, Optional[str]]:
        logger.info(f"target '{self.endpoint}' executing attack type '{label}'")
        try:
            result: TurnResult = _run_sync(lambda: self._send(payload))
        except Exception as exc:
            self.last_observation = {
                "stage": "target_request", "status": "error", "endpoint": self.endpoint,
                "error_type": type(exc).__name__,
            }
            log_event(logger, "target_error", **self.last_observation)
            return f"(target error: {type(exc).__name__})", None
        obs: Dict[str, Any] = {
            "stage": "target_request",
            "status": "response" if result.error is None else result.error.kind.value,
            "endpoint": self.endpoint,
            "http_status": result.http_status,
            "latency_ms": round(result.latency_ms, 2),
            "request_hash": result.request_hash,
            "response_hash": result.response_hash,
            "response_bytes": result.response_bytes,
        }
        if result.error is not None:
            obs["error_type"] = result.error.kind.value
        self.last_observation = obs
        log_event(logger, "target_response" if result.error is None else "target_error", **obs)
        if result.error is not None:
            return f"(target error: {result.error})", None
        return result.response_text, None


__all__ = ["SessionTargetAdapter", "TargetAdapter"]
