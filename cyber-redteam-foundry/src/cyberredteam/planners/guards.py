"""Planner guard rails (WP4), enforced in code for every planner.

Checks run on each outgoing message, in this order (cheapest first):

1. refusal text (LLMPlanner only; the structural ``refused`` flag is checked
   by the planner before this)
2. per-message length cap: over-length messages are REJECTED, never
   truncated, because a truncated message is text nobody wrote or reviewed
3. hard-refusal deny categories (kept from ``prompts/attacker.md``)
4. technique scope, through an injected :class:`ScopeClassifier`

Any failed check raises a :class:`PlannerGuardrailStop` subclass after one
structured log event. Log events and exception text carry ids, the technique,
a reason code and a category name; never the message text.

The default deny patterns are short category-level terms. They are a
backstop, not a classifier: real-person targeting in particular cannot be
caught reliably with patterns, so the scope classifier and the security
owner's planner prompt remain the primary controls.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from cyberredteam.logging import log_event
from cyberredteam.planners.errors import (
    PlannerDenyCategory,
    PlannerGuardrailStop,
    PlannerMessageTooLong,
    PlannerRefused,
    PlannerScopeViolation,
)

logger = logging.getLogger("cyberredteam.planners")

DEFAULT_MAX_MESSAGE_CHARS = 4000


# ── Scope classifier ─────────────────────────────────────────────────────────


@runtime_checkable
class ScopeClassifier(Protocol):
    """Return True only if ``message`` stays inside ``technique``'s scope."""

    def __call__(self, technique: str, message: str) -> bool: ...


# ── Deny categories ──────────────────────────────────────────────────────────

# Category-level terms only (hard-refusal list of prompts/attacker.md, plus
# real weapons and real-person targeting). Matching is case-insensitive on
# whitespace-normalised text. False positives end the conversation as an
# error, which is the safe direction.
DEFAULT_DENY_CATEGORIES: dict[str, tuple[str, ...]] = {
    "csam": (
        r"\bcsam\b",
        r"\bchild (sexual|porn)",
        r"\bsexual\w*\b.{0,40}\b(minor|minors|child|children|underage)\b",
        r"\b(minor|minors|child|children|underage)\b.{0,40}\bsexual",
    ),
    "cbrn_weapons": (
        r"\b(bio|biological|chemical|nuclear|radiological)[- ]?weapons?\b",
        r"\bnerve agents?\b",
        r"\bweaponi[sz]\w*\b.{0,40}\b(pathogen|virus|bacteri\w*|toxin|spores?)\b",
        r"\b(enrich\w*) uranium\b",
        r"\bdirty bomb\b",
    ),
    "conventional_weapons": (
        r"\b(build|make|assemble|manufacture|3d[- ]print)\w*\b.{0,40}\b(bomb|explosive|ied|firearm|gun|silencer)s?\b",
        r"\bpipe bomb\b",
        r"\bghost gun\b",
    ),
    "mass_casualty": (
        r"\bmass[- ]casualt",
        r"\bmass shooting\b",
        r"\bterror(ist)? attack\b",
    ),
    "real_person_targeting": (
        r"\bdox+\w*\b",
        r"\bswatting\b",
        r"\bhome address of\b",
    ),
}


def _normalise(text: str) -> str:
    return " ".join(text.replace("’", "'").split()).lower()


class DenyCategoryChecker:
    """Category check on planner output. ``check`` returns the first matching
    category name (in mapping order), or ``None``."""

    def __init__(self, categories: Mapping[str, Sequence[str]]) -> None:
        if not categories:
            raise ValueError("deny checker needs at least one category")
        self._compiled: list[tuple[str, list[re.Pattern[str]]]] = []
        for name, patterns in categories.items():
            if not name or not patterns:
                raise ValueError("deny categories need a name and at least one pattern")
            self._compiled.append((name, [re.compile(p, re.IGNORECASE) for p in patterns]))

    @property
    def categories(self) -> list[str]:
        return [name for name, _ in self._compiled]

    def check(self, text: str) -> str | None:
        norm = _normalise(text)
        for name, patterns in self._compiled:
            if any(p.search(norm) for p in patterns):
                return name
        return None


def default_deny_checker() -> DenyCategoryChecker:
    return DenyCategoryChecker(DEFAULT_DENY_CATEGORIES)


# ── Refusal text ─────────────────────────────────────────────────────────────

_REFUSAL_PATTERNS = tuple(
    re.compile(p)
    for p in (
        r"^(i'm|i am) sorry\b.{0,40}\b(can't|cannot|won't|will not|unable|not able)\b",
        r"^sorry, but\b",
        r"^i (can't|cannot|won't|will not|am unable to|'m unable to|am not able to) "
        r"(help|assist|comply|do that|provide|create|generate|write|fulfil|fulfill|support|participate)",
        r"^as an ai\b",
        r"^i must (decline|refuse)\b",
        r"\bi (can't|cannot|won't|will not) (help|assist) with (this|that)( request)?\b",
    )
)


def looks_like_refusal(text: str) -> bool:
    """Conservative refusal-text check on a model's message (leading phrases
    plus one anywhere-phrase). A persona line that starts like a refusal also
    matches; that ends the conversation, which is the safe direction."""
    norm = _normalise(text)
    return any(p.search(norm) for p in _REFUSAL_PATTERNS)


# ── Guard rails ──────────────────────────────────────────────────────────────


@dataclass
class GuardRails:
    """The guard-rail chain shared by both planners.

    ``scope_classifier=None`` skips the scope check. Only ScriptedPlanner
    allows that (its packs are operator-reviewed and pinned to a technique);
    LLMPlanner refuses to start without a classifier.
    """

    max_message_chars: int = DEFAULT_MAX_MESSAGE_CHARS
    deny_checker: DenyCategoryChecker = field(default_factory=default_deny_checker)
    scope_classifier: ScopeClassifier | None = None
    check_refusal_text: bool = False

    def __post_init__(self) -> None:
        if self.max_message_chars < 1:
            raise ValueError("max_message_chars must be >= 1")

    def stop(
        self,
        exc_type: type[PlannerGuardrailStop],
        *,
        planner: str,
        technique: str,
        conversation_id: str | None,
        detail: str = "",
        llm_tokens: int = 0,
        llm_cost_usd: float = 0.0,
        **fields: object,
    ) -> PlannerGuardrailStop:
        """Log the stop as one structured event and return the exception to raise."""
        log_event(
            logger,
            exc_type.reason,
            planner=planner,
            technique=technique,
            conversation_id=conversation_id,
            detail=detail,
            **fields,
        )
        return exc_type(detail, llm_tokens=llm_tokens, llm_cost_usd=llm_cost_usd)

    def check(
        self,
        message: str,
        *,
        planner: str,
        technique: str,
        conversation_id: str | None = None,
        llm_tokens: int = 0,
        llm_cost_usd: float = 0.0,
        **fields: object,
    ) -> None:
        """Raise a guard-rail stop if ``message`` may not be sent."""

        def fail(exc_type: type[PlannerGuardrailStop], detail: str) -> PlannerGuardrailStop:
            return self.stop(
                exc_type, planner=planner, technique=technique, conversation_id=conversation_id,
                detail=detail, llm_tokens=llm_tokens, llm_cost_usd=llm_cost_usd, **fields,
            )

        if self.check_refusal_text and looks_like_refusal(message):
            raise fail(PlannerRefused, "refusal_text")
        if len(message) > self.max_message_chars:
            raise fail(PlannerMessageTooLong, f"length={len(message)} cap={self.max_message_chars}")
        category = self.deny_checker.check(message)
        if category is not None:
            raise fail(PlannerDenyCategory, f"category={category}")
        if self.scope_classifier is not None:
            try:
                in_scope = self.scope_classifier(technique, message) is True
            except Exception as exc:  # fail closed: a broken classifier stops the conversation
                raise fail(PlannerScopeViolation, f"classifier_error={type(exc).__name__}") from None
            if not in_scope:
                raise fail(PlannerScopeViolation, "classifier_denied")


__all__ = [
    "DEFAULT_DENY_CATEGORIES",
    "DEFAULT_MAX_MESSAGE_CHARS",
    "DenyCategoryChecker",
    "GuardRails",
    "ScopeClassifier",
    "default_deny_checker",
    "looks_like_refusal",
]
