"""Worker entry points (WP4) for ``settings.planner_factory`` / ``PLANNER_FACTORY``.

The WP7 worker resolves ``"package.module:callable"`` and uses the callable
directly as ``EngineDeps.planner_factory`` (``ConversationSpec -> TurnPlanner``):

* ``cyberredteam.planners.worker:scripted`` replays packs from
  ``settings.planner_packs_dir``. With no directory set, the pack set chosen by
  ``settings.planner_pack_set`` (``PLANNER_PACK_SET``: ``smoke`` (default),
  ``attacks`` or ``all``) is loaded from ``<project>/packs``.
* ``cyberredteam.planners.worker:llm`` uses the LLM planner. It fails closed:
  without ``prompts/planner.md`` (security owner) it raises
  ``PlannerPromptMissing``, and no scope classifier is configurable through
  settings yet, so it also raises ``ScopeClassifierMissing``. Either way every
  conversation ends ``error`` and nothing is sent to the target.

The real factory is built on the first conversation (packs are loaded and
validated once per process) and reused. A failed build is campaign-fatal and
reported once per campaign (see ``_LazyPlannerFactory``).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from cyberredteam.engine.types import ConversationSpec, TurnPlanner
from cyberredteam.planners.errors import PlannerFactoryUnavailable
from cyberredteam.planners.factory import PlannerKind, make_planner_factory

logger = logging.getLogger(__name__)


class _LazyPlannerFactory:
    """Builds the real factory once per process, and remembers a failed build
    per campaign: the first conversation of a campaign raises
    :class:`PlannerFactoryUnavailable` (campaign-fatal, so the engine fails the
    campaign once) and any other conversation of that campaign re-raises the
    same error without rebuilding or re-logging. A later campaign retries."""

    _MAX_FAILED = 256

    def __init__(self, kind: PlannerKind) -> None:
        self.kind = kind
        self._factory: Callable[[ConversationSpec], TurnPlanner] | None = None
        self._failed: dict[str, PlannerFactoryUnavailable] = {}
        self._lock = threading.Lock()

    def __call__(self, spec: ConversationSpec) -> TurnPlanner:
        with self._lock:
            failure = self._failed.get(spec.campaign_id)
            if failure is not None:
                raise failure
            if self._factory is None:
                try:
                    self._factory = make_planner_factory(self.kind)
                except Exception as exc:  # config errors, OSError, a missing LLM key...
                    failure = PlannerFactoryUnavailable(
                        f"planner factory {self.kind!r} unavailable ({type(exc).__name__})"
                    )
                    if len(self._failed) >= self._MAX_FAILED:
                        self._failed.pop(next(iter(self._failed)))
                    self._failed[spec.campaign_id] = failure
                    logger.error("%s", failure)
                    raise failure from None
            factory = self._factory
        return factory(spec)

    def reset(self) -> None:
        """Drop the cached factory and failures (tests, or after the packs change)."""
        with self._lock:
            self._factory = None
            self._failed.clear()


scripted = _LazyPlannerFactory("scripted")
llm = _LazyPlannerFactory("llm")

__all__ = ["llm", "scripted"]
