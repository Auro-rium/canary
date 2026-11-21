"""WP5 evaluation wired into the worker (lead wiring).

* :func:`make_evaluation` builds the per-campaign ``EngineDeps.evaluator`` and
  ``EngineDeps.aggregate_results`` from the v2 repositories.
* The evaluator calls ``evaluate_conversation(conversation_id, EvaluationDeps(...))``
  with the **id** (never a loaded conversation), so WP5 does the audited raw read
  as ``system:evaluator``.
* Fail closed: if the judge cannot be built (no ``BACKBOARD_API_KEY``, bad
  config) or evaluation raises (Backboard error, timeout, DB error), the
  verdict is ``inconclusive`` and the failure is logged by class name. It is
  never ``safe``/``failed`` and never crashes the campaign. A deterministic
  critical hit (monitors) still confirms by WP5's own rules, judge or not.
* The target's safety inputs (canary values, forbidden tools) come from
  ``load_target_safety_config``; see :func:`safety_config_for`.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cyberredteam.contracts import (
    Conversation,
    ConversationVerdict,
    JudgeVote,
    TargetConfig,
)
from cyberredteam.engine.types import CampaignAggregate
from cyberredteam.evaluation.judge import Judge
from cyberredteam.evaluation.pipeline import (
    EvaluationDeps,
    compute_technique_results,
    evaluate_conversation,
)
from cyberredteam.evaluation.verdict import EvaluationSettings, JudgeOutcome
from cyberredteam.monitors import TargetSafetyConfig, load_target_safety_config
from cyberredteam.storage.v2.repositories import (
    AuditRepo,
    CampaignRepo,
    ConversationRepo,
    FindingRepo,
    VerdictRepo,
)

logger = logging.getLogger(__name__)

DEFAULT_EVALUATION_TIMEOUT_S = 240.0  # below EngineDeps.evaluation_timeout_s (300)


class UnavailableJudge:
    """Stands in for the judge when it cannot be built: every vote is invalid, so
    WP5's verdict rules give ``inconclusive`` (or ``confirmed`` on a deterministic
    critical hit), never ``failed``."""

    def __init__(self, k: int, reason: str) -> None:
        self.k = k
        self.reason = reason

    async def judge(self, conversation: Conversation, **_: Any) -> JudgeOutcome:
        votes = [
            JudgeVote(
                vote_index=i, judgement="inconclusive", confidence=0.0,
                rationale=f"judge unavailable ({self.reason})",
            )
            for i in range(self.k)
        ]
        return JudgeOutcome(votes=votes, valid=[False] * self.k, k=self.k)


def build_judge(k: int, judge_factory: Callable[[int], Judge] | None = None) -> Judge | UnavailableJudge:
    """The real ``Judge(k=...)``, or :class:`UnavailableJudge` (logged) if it cannot be built."""
    try:
        return judge_factory(k) if judge_factory is not None else Judge(k=k)
    except Exception as exc:
        logger.error("judge unavailable (%s): verdicts will be inconclusive", type(exc).__name__)
        return UnavailableJudge(k, type(exc).__name__)


def safety_config_for(target: TargetConfig, directory: str | Path | None) -> TargetSafetyConfig:
    """Per-target canary values and forbidden tools.

    ``<directory>/<target_id>.yaml``, else ``<directory>/default.yaml``, else an
    empty config (no directory configured). A file that exists but is invalid
    raises, which fails the campaign instead of running it without its canaries.
    """
    if not directory:
        return TargetSafetyConfig()
    base = Path(directory)
    for name in (f"{target.target_id}.yaml", "default.yaml"):
        candidate = base / name
        if candidate.is_file():
            return load_target_safety_config(candidate)
    return TargetSafetyConfig()


def _inconclusive(conversation_id: str, reason: str) -> ConversationVerdict:
    return ConversationVerdict(
        conversation_id=conversation_id,
        verdict="inconclusive",
        judge_agreement=0.0,
        severity="info",
        asi_class="ASI01",
        rationale=f"verdict=inconclusive path=fail_closed: evaluation failed ({reason}); not a safety result",
    )


class CampaignEvaluator:
    """``EngineDeps.evaluator``: idempotent, fail-closed evaluation of one conversation."""

    def __init__(
        self,
        factory: Any,
        judge: Judge | UnavailableJudge,
        *,
        forbidden_tools: frozenset[str] = frozenset(),
        target_id: str | None = None,
        timeout_s: float = DEFAULT_EVALUATION_TIMEOUT_S,
        settings: EvaluationSettings | None = None,
    ) -> None:
        self._judge = judge
        self._forbidden = frozenset(forbidden_tools)
        self._target_id = target_id
        self._timeout_s = timeout_s
        self._settings = settings
        self.verdicts = VerdictRepo(factory)
        self.conversations = ConversationRepo(factory)
        self.campaigns = CampaignRepo(factory)
        self.findings = FindingRepo(factory)
        self.audit = AuditRepo(factory)

    def _deps(self) -> EvaluationDeps:
        # One EvaluationDeps per call: it carries per-call state (last_finding).
        extra: dict[str, Any] = {"settings": self._settings} if self._settings is not None else {}
        return EvaluationDeps(
            judge=self._judge,  # type: ignore[arg-type]
            verdicts=self.verdicts,
            conversations=self.conversations,
            campaigns=self.campaigns,
            findings=self.findings,
            audit=self.audit,
            target_id=self._target_id,
            forbidden_tools=self._forbidden,
            **extra,
        )

    async def __call__(self, conversation_id: str) -> ConversationVerdict | None:
        """The new verdict, or ``None`` when one was already stored (a resumed campaign)."""
        try:
            if self.verdicts.get(conversation_id) is not None:
                return None
        except Exception as exc:
            logger.error("verdict lookup failed for %s (%s)", conversation_id, type(exc).__name__)
        try:
            async with asyncio.timeout(self._timeout_s):
                return await evaluate_conversation(conversation_id, self._deps())
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # incl. TimeoutError; judge/Backboard/DB errors
            logger.error("evaluation of %s failed (%s): inconclusive", conversation_id, type(exc).__name__)
        try:
            stored = self.verdicts.get(conversation_id)
            if stored is not None:  # saved before a later step (finding upsert) failed: keep it
                return stored
            verdict = _inconclusive(conversation_id, "error")
            self.verdicts.save(verdict)
            return verdict
        except Exception as exc:
            logger.error("could not store the inconclusive verdict for %s (%s)", conversation_id, type(exc).__name__)
            return _inconclusive(conversation_id, "error")


def make_aggregator(factory: Any) -> Callable[[str], CampaignAggregate]:
    conversations, verdicts, campaigns = ConversationRepo(factory), VerdictRepo(factory), CampaignRepo(factory)

    def aggregate(campaign_id: str) -> CampaignAggregate:
        results = compute_technique_results(
            campaign_id, conversations=conversations, verdicts=verdicts, campaigns=campaigns
        )
        counts = Counter(v.verdict for v in verdicts.list_for_campaign(campaign_id))
        return CampaignAggregate(technique_results=results, verdict_counts=dict(counts))

    return aggregate


def make_evaluation(
    factory: Any,
    *,
    target_id: str,
    forbidden_tools: frozenset[str],
    judge_factory: Callable[[int], Judge] | None = None,
    timeout_s: float = DEFAULT_EVALUATION_TIMEOUT_S,
) -> tuple[CampaignEvaluator, Callable[[str], CampaignAggregate]]:
    settings = EvaluationSettings.from_env()
    judge = build_judge(settings.judge_votes, judge_factory)
    evaluator = CampaignEvaluator(
        factory, judge, forbidden_tools=forbidden_tools, target_id=target_id,
        timeout_s=timeout_s, settings=settings,
    )
    return evaluator, make_aggregator(factory)


__all__ = [
    "CampaignEvaluator",
    "UnavailableJudge",
    "build_judge",
    "make_aggregator",
    "make_evaluation",
    "safety_config_for",
]
