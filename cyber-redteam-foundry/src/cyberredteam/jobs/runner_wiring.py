"""Attach the real WP3 engine to the worker.

``make_runner(runtime, planner_factory=...)`` returns a ``CampaignRunner`` that
builds ``engine.EngineDeps`` (the DB-backed ``runtime.control`` as RunControl,
the ``EventLogSink`` as event sink, the v2 repos) and calls
``engine.run_campaign``. The engine is resumable and idempotent per campaign id,
emits ``campaign_started`` and the terminal event itself, and sets the terminal
status; ``jobs/execution.py`` only fills in what the engine did not.

The planner factory is injected (WP4 provides real planners). With none
configured the runner fails closed: ``NoPlannerConfigured("no planner configured")``.
``engine_options`` passes extra ``EngineDeps`` fields (``canary_values``,
``forbidden_tools``, ``on_call``, ``adapter_factory``, ...).
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

from cyberredteam.contracts import CampaignRequest
from cyberredteam.engine import EngineDeps, EngineRepos, PlannerFactory, run_campaign
from cyberredteam.jobs.events import EventLogSink
from cyberredteam.jobs.execution import CampaignRunner
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo, CampaignRepo, ConversationRepo

logger = logging.getLogger(__name__)


class NoPlannerConfigured(RuntimeError):
    """No planner factory is configured for this worker."""


def load_planner_factory(spec: str | None) -> PlannerFactory | None:
    """Resolve ``"package.module:callable"`` to a planner factory (``None`` if unset)."""
    if not spec:
        return None
    module_name, _, attr = spec.partition(":")
    if not module_name or not attr:
        raise ValueError("planner_factory must look like 'package.module:callable'")
    return getattr(importlib.import_module(module_name), attr)


def make_runner(
    runtime: Any,
    planner_factory: PlannerFactory | None = None,
    engine_options: dict[str, Any] | None = None,
) -> CampaignRunner:
    async def runner(request: CampaignRequest, campaign_id: str) -> Any:
        if planner_factory is None:
            logger.error("no planner configured: set PLANNER_FACTORY=package.module:callable")
            raise NoPlannerConfigured("no planner configured")
        deps = EngineDeps(
            repos=EngineRepos(
                conversations=ConversationRepo(runtime.factory),
                campaigns=CampaignRepo(runtime.factory),
                budget=BudgetLedgerRepo(runtime.factory),
            ),
            planner_factory=planner_factory,
            run_control=runtime.control,
            events=EventLogSink(runtime.events),
            **(engine_options or {}),
        )
        return await run_campaign(request, campaign_id, deps)

    return runner
