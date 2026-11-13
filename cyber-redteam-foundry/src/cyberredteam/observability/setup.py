"""One-call observability bootstrap (WP11).

``init_observability(settings, service_name="api")`` is called once at API
startup and once at worker startup (the worker call is wired by WP7 / the
lead: ``init_observability(get_settings(), service_name="worker",
providers={"queue_depth": ..., "active_campaigns": ..., "kill_switch": ...})``).

It is idempotent, never raises, and is a complete no-op when the optional
``weave``/``wandb`` packages are missing, ``WANDB_API_KEY`` is unset (offline
mode is the exception, for local runs) or ``WANDB_MODE=disabled``.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from typing import Any

from cyberredteam.observability import hooks, redact
from cyberredteam.observability.service import Provider, ServiceReporter
from cyberredteam.observability.wandb_metrics import WandbCampaignMetrics

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_handle: ObservabilityHandle | None = None


@dataclass
class ObservabilityHandle:
    enabled: bool = False
    tracing: bool = False
    metrics: Any = None
    reporter: ServiceReporter | None = None

    def shutdown(self) -> None:
        if self.reporter:
            self.reporter.stop()
        if self.metrics is not None and hasattr(self.metrics, "close"):
            self.metrics.close()


def _secret(value: Any) -> str | None:
    if value is None:
        return None
    getter = getattr(value, "get_secret_value", None)
    return (getter() if getter else str(value)) or None


def _packages_available() -> bool:
    try:
        import wandb  # noqa: F401

        return True
    except Exception:
        return False


def init_observability(
    settings: Any,
    service_name: str = "api",
    providers: dict[str, Provider] | None = None,
    oncall_webhook_url: str | None = None,
) -> ObservabilityHandle:
    global _handle
    with _lock:
        if _handle is not None:
            return _handle
        _handle = ObservabilityHandle()
        try:
            _handle = _init(settings, service_name, providers, oncall_webhook_url)
        except Exception as exc:  # observability must never break startup
            logger.warning("observability init failed: %s", exc)
        return _handle


def _init(settings: Any, service_name: str, providers: Any, webhook: str | None) -> ObservabilityHandle:
    mode = (getattr(settings, "wandb_mode", "online") or "online").lower()
    key = _secret(getattr(settings, "wandb_api_key", None))

    # Always mask known secrets in any export, even if W&B stays off.
    for name in ("backboard_api_key", "api_secret_key", "target_api_key", "canary_encryption_key"):
        redact.register_secret(_secret(getattr(settings, name, None)))
    redact.register_secret(key)
    redact.configure_raw_export(bool(getattr(settings, "wandb_export_raw_evidence", False)))

    if mode == "disabled" or not _packages_available() or (not key and mode != "offline"):
        return ObservabilityHandle()
    if key and not os.environ.get("WANDB_API_KEY"):
        os.environ["WANDB_API_KEY"] = key
    os.environ.setdefault("WANDB_SILENT", "true")

    entity = getattr(settings, "wandb_entity", None)
    project = getattr(settings, "wandb_project", "canary") or "canary"

    metrics = WandbCampaignMetrics(project=project, entity=entity, mode=mode,
                                   oncall_webhook_url=webhook)
    hooks.set_metrics(metrics)
    metrics.service_started(service_name, {"service": service_name})

    tracing = False
    if mode == "online" and key:
        from cyberredteam.observability.weave_tracing import init_tracing

        tracing = init_tracing(entity, project)

    reporter = ServiceReporter(metrics.service_log, providers)
    reporter.start()
    return ObservabilityHandle(True, tracing, metrics, reporter)


def reset_for_tests() -> None:
    """Drop the singleton and restore no-op hooks (tests only)."""
    global _handle
    with _lock:
        if _handle is not None:
            _handle.shutdown()
        _handle = None
    hooks.set_metrics(hooks.NoopMetrics())
