"""Planner errors (WP4).

Two families:

* Configuration errors (``PlannerConfigError``) are raised when a planner or a
  planner factory is built. They stop a campaign before any turn is sent.
* Guard-rail stops (``PlannerGuardrailStop``) are raised from ``next_turn``.
  The WP3 engine maps any planner exception to the conversation status
  ``error``. That is deliberate: a guard-rail stop must never look like a
  clean ``completed`` conversation, so a planner never reports one by
  returning ``end_conversation=True``.

Exception messages carry reason codes and ids only, never message text.
"""

from __future__ import annotations


class PlannerError(Exception):
    """Base class for every planner error."""


# ── Configuration (raised at construction) ───────────────────────────────────


class PlannerConfigError(PlannerError):
    """The planner cannot be built as configured."""


class PlannerPromptMissing(PlannerConfigError):
    """``prompts/planner.md`` is missing or empty. LLMPlanner fails closed."""


class ScopeClassifierMissing(PlannerConfigError):
    """LLMPlanner was built without a technique-scope classifier."""


class PackError(PlannerConfigError):
    """A turn-script pack is invalid or cannot be found."""


class PackValidationError(PackError):
    """A pack file does not match the pack schema."""


class PackNotFound(PackError):
    """No pack matches the requested name or technique."""


class TechniqueMismatch(PackError):
    """The pack's technique differs from the conversation's technique."""


# ── Guard-rail stops (raised from next_turn) ─────────────────────────────────


class PlannerGuardrailStop(PlannerError):
    """A guard rail ended the conversation.

    ``reason`` is the logged event code. ``llm_tokens`` / ``llm_cost_usd`` is
    what the planner call cost (from provider usage) before it was stopped. The
    WP3 engine does not charge spend for a raised planner, so these fields let a
    future engine change charge it (see the WP4 status in the build plan).
    """

    reason: str = "planner_guardrail"

    def __init__(self, detail: str = "", *, llm_tokens: int = 0, llm_cost_usd: float = 0.0) -> None:
        self.detail = detail
        self.llm_tokens = llm_tokens
        self.llm_cost_usd = llm_cost_usd
        super().__init__(f"{self.reason}: {detail}" if detail else self.reason)


class PlannerRefused(PlannerGuardrailStop):
    """The planner model refused (structural flag or refusal text)."""

    reason = "planner_refused"


class PlannerMessageTooLong(PlannerGuardrailStop):
    """The message exceeds the per-message length cap. It is rejected, not truncated."""

    reason = "planner_message_too_long"


class PlannerDenyCategory(PlannerGuardrailStop):
    """The message matches a hard-refusal category."""

    reason = "planner_deny_category"


class PlannerScopeViolation(PlannerGuardrailStop):
    """The scope classifier says the message is outside the technique (or failed)."""

    reason = "planner_out_of_scope"


class PlannerInvalidOutput(PlannerGuardrailStop):
    """The planner produced no usable message (e.g. empty without ending)."""

    reason = "planner_invalid_output"


__all__ = [
    "PackError",
    "PackNotFound",
    "PackValidationError",
    "PlannerConfigError",
    "PlannerDenyCategory",
    "PlannerError",
    "PlannerGuardrailStop",
    "PlannerInvalidOutput",
    "PlannerMessageTooLong",
    "PlannerPromptMissing",
    "PlannerRefused",
    "PlannerScopeViolation",
    "ScopeClassifierMissing",
    "TechniqueMismatch",
]
