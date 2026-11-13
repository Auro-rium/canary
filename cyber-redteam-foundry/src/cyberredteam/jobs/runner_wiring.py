"""The single place where the real WP3 runner is attached to the worker.

WP3 exposes ``cyberredteam.engine.runner.run_campaign(request, campaign_id,
deps) -> CampaignOutcome`` (resumable, idempotent, calls ``RunControl.check``
before every turn). The lead wires it here after WP3 merges:

    from cyberredteam.engine.runner import run_campaign

    def make_runner(runtime):
        deps = build_engine_deps(runtime.factory, runtime.control)  # EngineDeps
        async def runner(request, campaign_id):
            return await run_campaign(request, campaign_id, deps)
        return runner

``deps`` must use ``runtime.control`` (the ``DbRunControl``) as its RunControl and
may use ``runtime.events.append`` to emit SSE events (per-campaign ``seq``).

Until then the default runner raises, so a worker with no runner fails every
campaign closed instead of silently skipping it.
"""

from __future__ import annotations

from cyberredteam.contracts import CampaignRequest
from cyberredteam.jobs.execution import CampaignRunner


class RunnerNotWired(RuntimeError):
    pass


async def _not_wired(request: CampaignRequest, campaign_id: str) -> None:
    raise RunnerNotWired("engine runner is not wired into the worker (jobs/runner_wiring.py)")


def make_runner(runtime=None) -> CampaignRunner:  # noqa: ARG001 - runtime used once wired
    return _not_wired
