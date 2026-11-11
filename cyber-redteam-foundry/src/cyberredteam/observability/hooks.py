"""Observability seam shared by WP3/WP7 (callers) and WP11 (implementation).

Frozen interface. Callers use only:

* ``trace_op(name)``: decorator for sync or async functions; WP11 maps it to
  ``weave.op`` with redaction. Default: returns the function unchanged.
* ``get_metrics()``: returns the process-wide :class:`CampaignMetrics` sink.
  Default: :class:`NoopMetrics`.

WP11 installs real implementations via ``set_tracer`` / ``set_metrics`` at
startup. Every implementation must never raise into the caller: observability
failures are swallowed and logged, and campaigns always complete.
"""

from __future__ import annotations

from typing import Any, Callable, Protocol, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


class CampaignMetrics(Protocol):
    def campaign_started(self, campaign_id: str, config: dict[str, Any]) -> None: ...
    def log(self, campaign_id: str, metrics: dict[str, float], step: int | None = None) -> None: ...
    def campaign_finished(self, campaign_id: str, summary: dict[str, Any]) -> None: ...
    def alert(self, title: str, text: str, level: str = "WARN") -> None: ...


class NoopMetrics:
    def campaign_started(self, campaign_id: str, config: dict[str, Any]) -> None:
        return None

    def log(self, campaign_id: str, metrics: dict[str, float], step: int | None = None) -> None:
        return None

    def campaign_finished(self, campaign_id: str, summary: dict[str, Any]) -> None:
        return None

    def alert(self, title: str, text: str, level: str = "WARN") -> None:
        return None


def _identity_tracer(name: str) -> Callable[[F], F]:
    def deco(fn: F) -> F:
        return fn

    return deco


_tracer: Callable[[str], Callable[[Any], Any]] = _identity_tracer
_metrics: CampaignMetrics = NoopMetrics()


def trace_op(name: str) -> Callable[[F], F]:
    """Decorate an operation for tracing. Resolved at decoration time."""
    return _tracer(name)


def set_tracer(tracer: Callable[[str], Callable[[Any], Any]]) -> None:
    global _tracer
    _tracer = tracer


def get_metrics() -> CampaignMetrics:
    return _metrics


def set_metrics(metrics: CampaignMetrics) -> None:
    global _metrics
    _metrics = metrics
