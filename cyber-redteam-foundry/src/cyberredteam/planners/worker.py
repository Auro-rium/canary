"""Worker entry points (WP4) for ``settings.planner_factory`` / ``PLANNER_FACTORY``.

The WP7 worker resolves ``"package.module:callable"`` and uses the callable
directly as ``EngineDeps.planner_factory`` (``ConversationSpec -> TurnPlanner``):

* ``cyberredteam.planners.worker:scripted`` replays packs from
  ``settings.planner_packs_dir`` (default ``<project>/packs``).
* ``cyberredteam.planners.worker:llm`` uses the LLM planner. It fails closed:
  without ``prompts/planner.md`` (security owner) it raises
  ``PlannerPromptMissing``, and no scope classifier is configurable through
  settings yet, so it also raises ``ScopeClassifierMissing``. Either way every
  conversation ends ``error`` and nothing is sent to the target.

The real factory is built on the first conversation (packs are loaded and
validated once per process) and reused.
"""

from __future__ import annotations

import threading
from collections.abc import Callable

from cyberredteam.engine.types import ConversationSpec, TurnPlanner
from cyberredteam.planners.factory import PlannerKind, make_planner_factory


class _LazyPlannerFactory:
    def __init__(self, kind: PlannerKind) -> None:
        self.kind = kind
        self._factory: Callable[[ConversationSpec], TurnPlanner] | None = None
        self._lock = threading.Lock()

    def __call__(self, spec: ConversationSpec) -> TurnPlanner:
        with self._lock:
            if self._factory is None:
                self._factory = make_planner_factory(self.kind)
            factory = self._factory
        return factory(spec)

    def reset(self) -> None:
        """Drop the cached factory (tests, or after the packs change)."""
        with self._lock:
            self._factory = None


scripted = _LazyPlannerFactory("scripted")
llm = _LazyPlannerFactory("llm")

__all__ = ["llm", "scripted"]
