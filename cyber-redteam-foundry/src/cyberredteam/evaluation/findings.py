"""Findings from conversation verdicts (WP5, gaps B7 and B9).

* **Identity (B7).** ``finding_id = sha256(target_id:component:technique:asi_class)[:16]``
  with the *real* component: ``tool:<name>`` for the structured tool call at the
  failing turn (a forbidden one first), else ``reply`` for leaks in reply text.
  Different tools no longer collapse into one finding.
* **Lifecycle (B9).** ``confirmed`` opens (or re-opens from ``needs_review`` /
  ``inconclusive``) an ``open`` finding. ``inconclusive`` and ``unconfirmed``
  (judge-only or contradicted evidence) open a ``needs_review`` finding so they
  reach triage. ``failed`` (target behaved safely) opens nothing. A new row is
  created atomically in its final status (``FindingRepo.upsert(initial_status=)``),
  so there is no create-as-open-then-transition window. Merging into an existing
  row never demotes it: a weaker verdict only adds a sighting; the only status
  change made here is the promotion to ``open``, and only when the current
  status was set by automation (a human triage decision is never overridden). Terminal findings are never
  reopened. ``needs_review`` already exists in the v2 schema (no migration).
* **Semantic dedup.** With an embedder, a new finding whose embedding is at least
  ``dedup_threshold`` (cosine) similar to an existing non-terminal finding of the
  same target is *merged* into it (a sighting is added) instead of creating a
  near-duplicate. **Human override:** :func:`mark_distinct` records (audited) that a
  finding must never absorb new findings by similarity, and ``dedup=False``
  disables merging for a call. Without an embedder only exact ids merge.

Titles and embeddings use technique, component, ASI class and hit names only,
never evidence text (findings are not redacted at rest).
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from cyberredteam.contracts import Conversation, ConversationVerdict
from cyberredteam.monitors.base import classify_hit
from cyberredteam.monitors.tools import normalise_tool_name
from cyberredteam.storage.v2.repositories import (
    DEDUP_THRESHOLD,
    TERMINAL_FINDING_STATUSES,
    AuditRepo,
    FindingRecord,
    FindingRepo,
    FindingStatus,
    InvalidTransition,
)

logger = logging.getLogger(__name__)

Embedder = Callable[[str], "list[float] | None"]
SYSTEM_REVIEWER = "system:evaluator"
DEDUP_OVERRIDE_ACTION = "finding.dedup_override"
DEDUP_MERGED_ACTION = "finding.dedup_merged"
PROMOTION_SKIPPED_ACTION = "finding.promotion_skipped"

_PROMOTABLE = frozenset({"needs_review", "inconclusive"})
_VERDICT_STATUS: dict[str, FindingStatus] = {
    "confirmed": "open",
    "unconfirmed": "needs_review",
    "inconclusive": "needs_review",
}


def finding_id(target_id: str, component: str, technique: str, asi_class: str) -> str:
    key = f"{target_id}:{component}:{technique}:{asi_class}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def resolve_component(
    conversation: Conversation,
    verdict: ConversationVerdict,
    forbidden_tools: frozenset[str] | set[str] = frozenset(),
) -> str:
    """``tool:<name>`` of the structured call at the failing turn, else ``reply``.

    Names go through the same :func:`monitors.tools.normalise_tool_name` the
    forbidden-tool monitor uses (lower case, only the ``functions.`` wrapper
    removed), so ``functions.delete_record`` and ``delete_record`` are one
    component, while ``a.delete_record`` and ``b.delete_record`` stay distinct."""
    index = verdict.first_failing_turn
    if index is None:
        for t in conversation.turns:
            if any(classify_hit(h).evidence for h in t.monitor_hits):
                index = t.index
                break
    if index is None or not 0 <= index < len(conversation.turns):
        return "reply"
    structured = [c for c in conversation.turns[index].tool_calls if c.source == "structured"]
    if not structured:
        return "reply"
    forbidden = {normalise_tool_name(f) for f in forbidden_tools if f}
    chosen = next((c for c in structured if normalise_tool_name(c.name) in forbidden), structured[0])
    return f"tool:{normalise_tool_name(chosen.name)}"


def finding_title(technique: str, component: str, asi_class: str) -> str:
    return f"{technique} via {component} ({asi_class})"


def _embedding_text(record: FindingRecord, hits: list[str]) -> str:
    return " | ".join([record.title, record.technique, record.component, record.asi_class, *hits])


def mark_distinct(audit: AuditRepo, finding_id_: str, *, reviewer_id: str, rationale: str) -> None:
    """Human override: never merge new findings into ``finding_id_`` by similarity."""
    if not reviewer_id.strip() or not rationale.strip():
        raise ValueError("a dedup override needs reviewer_id and rationale")
    audit.record(reviewer_id, DEDUP_OVERRIDE_ACTION, f"finding:{finding_id_}", {"rationale": rationale})


def dedup_overrides(audit: AuditRepo | None) -> set[str]:
    if audit is None:
        return set()
    return {
        e.object.split(":", 1)[1]
        for e in audit.list(action=DEDUP_OVERRIDE_ACTION)
        if e.object.startswith("finding:")
    }


@dataclass(frozen=True)
class FindingOutcome:
    record: FindingRecord
    action: Literal["created", "merged_exact", "merged_similar"]
    merged_into: str | None = None
    similarity: float | None = None


def upsert_finding_for_verdict(
    verdict: ConversationVerdict,
    conversation: Conversation,
    *,
    target_id: str,
    campaign_id: str | None,
    findings: FindingRepo,
    audit: AuditRepo | None = None,
    embedder: Embedder | None = None,
    dedup: bool = True,
    dedup_threshold: float = DEDUP_THRESHOLD,
    forbidden_tools: frozenset[str] | set[str] = frozenset(),
) -> FindingOutcome | None:
    """Create or merge the finding for one verdict; ``None`` for ``failed``."""
    desired = _VERDICT_STATUS.get(verdict.verdict)
    if desired is None:
        return None
    component = resolve_component(conversation, verdict, forbidden_tools)
    technique = conversation.technique
    record = FindingRecord(
        finding_id=finding_id(target_id, component, technique, verdict.asi_class),
        target_id=target_id,
        component=component,
        technique=technique,
        asi_class=verdict.asi_class,
        severity=verdict.severity,
        title=finding_title(technique, component, verdict.asi_class),
        conversation_id=conversation.conversation_id,
    )

    existing = findings.get(record.finding_id)
    action: Literal["created", "merged_exact", "merged_similar"] = (
        "merged_exact" if existing else "created"
    )
    merged_into: str | None = None
    similarity: float | None = None
    embedding: list[float] | None = None
    if embedder is not None:
        try:
            embedding = embedder(_embedding_text(record, verdict.deterministic_hits))
        except Exception as exc:
            logger.warning("finding embedding failed: %s", type(exc).__name__)
            embedding = None

    if existing is None and dedup and embedding is not None:
        blocked = dedup_overrides(audit)
        for cand_id, sim in findings.find_similar(
            target_id, embedding, threshold=dedup_threshold, open_only=False
        ):
            cand = findings.get(cand_id)
            if cand is None or cand.status in TERMINAL_FINDING_STATUSES or cand_id in blocked:
                continue
            existing, merged_into, similarity = cand, cand_id, sim
            action = "merged_similar"
            record = record.model_copy(update={"finding_id": cand_id})
            break

    # Created atomically in its final status; an existing row keeps its status
    # (a weaker verdict only adds a sighting, never demotes open → needs_review).
    saved = findings.upsert(
        record, campaign_id=campaign_id, embedding=embedding, initial_status=desired
    )
    if merged_into and audit is not None:
        audit.record(
            SYSTEM_REVIEWER, DEDUP_MERGED_ACTION, f"finding:{merged_into}",
            {"similarity": round(similarity or 0.0, 4), "conversation_id": conversation.conversation_id,
             "component": component},
        )

    # The only status change made here is a promotion to open by a confirmed
    # verdict, and only over a status that automation set: a human triage
    # decision (e.g. alice moved it open -> needs_review) is never overridden.
    # The repo checks both inside the transaction with a compare-and-set.
    if desired == "open" and saved.status in _PROMOTABLE:
        reason = f"confirmed verdict for conversation {conversation.conversation_id}"
        try:
            saved = findings.transition(
                saved.finding_id, "open", reviewer_id=SYSTEM_REVIEWER, rationale=reason,
                expected_from=saved.status, require_system_last=True,
            )
        except InvalidTransition as exc:
            # A human decided, or another writer won the race: keep their status
            # and record only the sighting (done by the upsert above).
            saved = findings.get(saved.finding_id) or saved
            if audit is not None:
                audit.record(
                    SYSTEM_REVIEWER, PROMOTION_SKIPPED_ACTION, f"finding:{saved.finding_id}",
                    {"reason": str(exc), "status": saved.status,
                     "conversation_id": conversation.conversation_id},
                )
    return FindingOutcome(saved, action, merged_into, similarity)


__all__ = [
    "DEDUP_MERGED_ACTION",
    "DEDUP_OVERRIDE_ACTION",
    "PROMOTION_SKIPPED_ACTION",
    "Embedder",
    "FindingOutcome",
    "dedup_overrides",
    "finding_id",
    "finding_title",
    "mark_distinct",
    "resolve_component",
    "upsert_finding_for_verdict",
]
