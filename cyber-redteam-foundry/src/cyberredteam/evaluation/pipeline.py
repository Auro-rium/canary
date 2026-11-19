"""WP5 wire-up: judge a finished conversation, persist the verdict, upsert findings.

Call sites for the lead (not wired here; engine/* and jobs/* are not WP5's):

1. **Monitors**: build ``EngineDeps(monitors=cyberredteam.monitors.build_monitors(), ...)``.
   It *replaces* the builtin monitor (same hit names, superset of rules).
2. **Per conversation**: after ``run_conversation`` returns a terminal status
   (in ``engine.runner`` right after the conversation finishes, or in the WP7
   worker), call::

       verdict = await evaluate_conversation(conversation_id, deps)

   Pass the **id** (or a Conversation loaded with
   ``ConversationRepo.get(id, raw=True, actor=...)``): the default repo read is
   redacted and truncated, and judging that would bring back B5. With an id,
   this module does the audited raw read as ``system:evaluator``.
   Then emit the SSE ``verdict`` event and, for ``stop_on_first_confirmed``,
   check ``verdict.verdict == "confirmed"``.
3. **Per campaign**: after all conversations, call
   ``compute_technique_results(campaign_id, deps)`` (stores them with
   ``CampaignRepo.save_technique_results``) and use the confirmed count for
   ``campaign_complete.confirmed``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cyberredteam.contracts import Conversation, ConversationVerdict, TechniqueResult
from cyberredteam.evaluation.aggregate import aggregate
from cyberredteam.evaluation.findings import (
    Embedder,
    FindingOutcome,
    resolve_component,
    upsert_finding_for_verdict,
)
from cyberredteam.evaluation.judge import Judge
from cyberredteam.evaluation.taxonomy import lookup as taxonomy_lookup
from cyberredteam.evaluation.technique_specs import get_spec
from cyberredteam.evaluation.verdict import EvaluationSettings, decide_verdict
from cyberredteam.observability.hooks import trace_op
from cyberredteam.storage.v2.repositories import (
    AuditRepo,
    CampaignRepo,
    ConversationRepo,
    FindingRepo,
    VerdictRepo,
)

EVALUATOR_ACTOR = "system:evaluator"


@dataclass
class EvaluationDeps:
    """Everything evaluation needs. ``target_id`` is read from the campaign when
    not given. ``findings=None`` skips finding upserts (e.g. calibration)."""

    judge: Judge
    verdicts: VerdictRepo | None = None
    conversations: ConversationRepo | None = None
    campaigns: CampaignRepo | None = None
    findings: FindingRepo | None = None
    audit: AuditRepo | None = None
    target_id: str | None = None
    forbidden_tools: frozenset[str] = frozenset()
    settings: EvaluationSettings = field(default_factory=EvaluationSettings.from_env)
    embedder: Embedder | None = None
    dedup: bool = True
    last_finding: FindingOutcome | None = None


def asi_class_for(technique: str, component: str = "") -> str:
    tool = component.split(":", 1)[1] if component.startswith("tool:") else ""
    return taxonomy_lookup(technique, tool)[0] or "ASI01"


async def judge_conversation(
    conversation: Conversation,
    judge: Judge,
    *,
    settings: EvaluationSettings | None = None,
    forbidden_tools: frozenset[str] = frozenset(),
) -> ConversationVerdict:
    """Pure evaluation (no persistence): judge votes + verdict rules."""
    settings = settings or EvaluationSettings()
    asi = asi_class_for(conversation.technique)
    hits = list(dict.fromkeys(h for t in conversation.turns for h in t.monitor_hits))
    outcome = await judge.judge(conversation, technique_spec=get_spec(asi), deterministic_hits=hits)
    verdict = decide_verdict(conversation, outcome, asi_class=asi, settings=settings)
    refined = asi_class_for(conversation.technique, resolve_component(conversation, verdict, forbidden_tools))
    if refined != verdict.asi_class:
        verdict = verdict.model_copy(update={"asi_class": refined})
    return verdict


def _load(conversation: Conversation | str, deps: EvaluationDeps) -> Conversation:
    if isinstance(conversation, Conversation):
        return conversation
    if deps.conversations is None:
        raise ValueError("a conversation id needs EvaluationDeps.conversations")
    loaded = deps.conversations.get(conversation, raw=True, actor=EVALUATOR_ACTOR)
    if loaded is None:
        raise KeyError(conversation)
    return loaded


@trace_op("evaluation.conversation")
async def evaluate_conversation(
    conversation: Conversation | str, deps: EvaluationDeps
) -> ConversationVerdict:
    """Judge, decide, persist to ``VerdictRepo`` and upsert the finding."""
    conv = _load(conversation, deps)
    verdict = await judge_conversation(
        conv, deps.judge, settings=deps.settings, forbidden_tools=deps.forbidden_tools
    )
    if deps.verdicts is not None:
        deps.verdicts.save(verdict)
    if deps.findings is not None:
        target_id = deps.target_id
        if target_id is None and deps.campaigns is not None:
            record = deps.campaigns.get(conv.campaign_id)
            target_id = record.target_id if record else None
        if target_id is None:
            raise ValueError("finding upsert needs target_id (or campaigns to look it up)")
        deps.last_finding = upsert_finding_for_verdict(
            verdict,
            conv,
            target_id=target_id,
            campaign_id=conv.campaign_id,
            findings=deps.findings,
            audit=deps.audit,
            embedder=deps.embedder,
            dedup=deps.dedup,
            dedup_threshold=deps.settings.dedup_threshold,
            forbidden_tools=deps.forbidden_tools,
        )
    return verdict


def compute_technique_results(
    campaign_id: str,
    *,
    conversations: ConversationRepo,
    verdicts: VerdictRepo,
    campaigns: CampaignRepo,
) -> list[TechniqueResult]:
    """Aggregate every conversation of a campaign and store the TechniqueResults."""
    by_id = {v.conversation_id: v for v in verdicts.list_for_campaign(campaign_id)}
    pairs = []
    for cid in conversations.list_for_campaign(campaign_id):
        conv = conversations.get(cid)  # redacted read: only the technique is used
        if conv is not None:
            pairs.append((conv.technique, by_id.get(cid)))
    results = aggregate(pairs).results
    campaigns.save_technique_results(campaign_id, results)
    return results


__all__ = [
    "EVALUATOR_ACTOR",
    "EvaluationDeps",
    "asi_class_for",
    "compute_technique_results",
    "evaluate_conversation",
    "judge_conversation",
]
