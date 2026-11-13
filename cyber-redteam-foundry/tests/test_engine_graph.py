# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""WP3 LangGraph v2 graph: conversation_branch is a thin adapter over the engine."""

from __future__ import annotations

import asyncio

from engine_support import _key, build, factory, new_campaign_id  # noqa: F401

from cyberredteam.engine import plan_conversations
from cyberredteam.langgraph.campaign_graph import build_campaign_graph, run_campaign_graph


def test_graph_has_conversation_branch_not_attacker_branch():
    nodes = set(build_campaign_graph().compile().get_graph().nodes)
    assert "conversation_branch" in nodes and "attacker_branch" not in nodes


def test_graph_runs_campaign_with_cap_and_persists(factory):
    h = build(factory, techniques=["a", "b"], trials_per_technique=3, max_turns=2,
              max_parallel_conversations=2)
    campaign = new_campaign_id()
    outcome = asyncio.run(run_campaign_graph(h.request, campaign, h.deps))
    assert outcome.status == "completed"
    assert [c.conversation_id for c in outcome.conversations] == [
        s.conversation_id for s in plan_conversations(h.request, campaign)
    ]
    assert all(c.status == "completed" and c.turns == 2 for c in outcome.conversations)
    assert h.max_active == 2
    assert len(h.fake.requests) == 12
    assert {r.headers["x-canary-campaign"] for r in h.fake.requests} == {campaign}

    # Re-running through the graph is idempotent too.
    h2 = build(factory, techniques=["a", "b"], trials_per_technique=3, max_turns=2)
    again = asyncio.run(run_campaign_graph(h.request, campaign, h2.deps))
    assert all(c.skipped for c in again.conversations)


def test_graph_kill_switch(factory):
    h = build(factory, techniques=["a"], trials_per_technique=4, max_turns=8,
              max_parallel_conversations=4)

    async def on_event(event_type, payload):
        if event_type == "turn" and payload.index == 1:
            await h.control.kill_all()

    h.events.hook = on_event
    outcome = asyncio.run(run_campaign_graph(h.request, new_campaign_id(), h.deps))
    assert outcome.status == "killed"
    assert all(c.turns <= 3 for c in outcome.conversations)
