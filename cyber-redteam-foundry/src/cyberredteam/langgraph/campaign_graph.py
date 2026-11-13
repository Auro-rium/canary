"""LangGraph v2 campaign graph (WP3): strategist -> Send(conversation_branch) xN -> collect.

For v2 campaigns ``conversation_branch`` replaces the legacy ``attacker_branch``.
The legacy v1 graph in ``graph.py`` is untouched.

The node is a thin adapter over the engine: :func:`cyberredteam.engine.run_conversation`
does all the work, and :func:`cyberredteam.engine.run_campaign` remains the
primary entry point (WP7 may use either). Non-serialisable runtime objects (the
:class:`~cyberredteam.engine.CampaignRuntime` and the semaphore) travel in
``config["configurable"]``, never in graph state, so a checkpointer would only
ever see plain data. Durable resume does not need a LangGraph checkpointer: it
comes from the per-turn DB writes and deterministic conversation ids, so the
graph is compiled without one.
"""

from __future__ import annotations

import asyncio
import operator
from typing import Annotated, Any

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph
from langgraph.types import Send
from typing_extensions import TypedDict

from cyberredteam.contracts import CampaignRequest
from cyberredteam.engine.runner import (
    CampaignOutcome,
    ConversationResult,
    EngineDeps,
    begin_campaign,
    fail_campaign,
    finish_campaign,
    plan_conversations,
    run_conversation,
)
from cyberredteam.engine.types import ConversationSpec
from cyberredteam.observability.hooks import trace_op

RUNTIME_KEY = "campaign_runtime"
SEMAPHORE_KEY = "conversation_semaphore"


class CampaignGraphState(TypedDict):
    campaign_id: str
    specs: list[dict[str, Any]]
    results: Annotated[list[dict[str, Any]], operator.add]


def _configurable(config: RunnableConfig) -> dict[str, Any]:
    return (config or {}).get("configurable", {})


def node_strategist(state: CampaignGraphState, config: RunnableConfig) -> dict:
    runtime = _configurable(config)[RUNTIME_KEY]
    specs = plan_conversations(runtime.request, state["campaign_id"])
    return {"specs": [s.model_dump() for s in specs]}


def dispatch_conversations(state: CampaignGraphState) -> list[Send]:
    return [Send("conversation_branch", {"spec": spec}) for spec in state["specs"]]


async def node_conversation_branch(payload: dict[str, Any], config: RunnableConfig) -> dict:
    conf = _configurable(config)
    spec = ConversationSpec.model_validate(payload["spec"])
    async with conf[SEMAPHORE_KEY]:
        result = await run_conversation(spec, conf[RUNTIME_KEY])
    return {"results": [result.model_dump()]}


def node_collect(state: CampaignGraphState) -> dict:
    return {}


def build_campaign_graph() -> StateGraph:
    graph = StateGraph(CampaignGraphState)
    graph.add_node("strategist", node_strategist)
    graph.add_node("conversation_branch", node_conversation_branch)
    graph.add_node("collect", node_collect)
    graph.set_entry_point("strategist")
    graph.add_conditional_edges("strategist", dispatch_conversations, ["conversation_branch"])
    graph.add_edge("conversation_branch", "collect")
    graph.add_edge("collect", END)
    return graph


@trace_op("engine.run_campaign_graph")
async def run_campaign_graph(
    request: CampaignRequest, campaign_id: str, deps: EngineDeps
) -> CampaignOutcome:
    """Same contract as :func:`cyberredteam.engine.run_campaign`, via LangGraph."""
    started = deps.clock()
    runtime = await begin_campaign(request, campaign_id, deps)
    config: RunnableConfig = {
        "configurable": {
            RUNTIME_KEY: runtime,
            SEMAPHORE_KEY: asyncio.Semaphore(request.policy.max_parallel_conversations),
        },
    }
    try:
        final = await build_campaign_graph().compile().ainvoke(
            {"campaign_id": campaign_id, "specs": [], "results": []}, config=config
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        await fail_campaign(runtime, exc)
        raise
    by_id = {r["conversation_id"]: ConversationResult.model_validate(r) for r in final["results"]}
    ordered = [
        by_id[ConversationSpec.model_validate(s).conversation_id] for s in final["specs"]
    ]
    return await finish_campaign(runtime, ordered, started)
