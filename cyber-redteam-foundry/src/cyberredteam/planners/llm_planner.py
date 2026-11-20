"""LLMPlanner (WP4): next turn from the planner model, behind code guard rails.

Mechanism only. The system prompt is ``prompts/planner.md``, owned and
reviewed by the security owner and NOT part of this repository's code. If it
is missing or empty, construction raises :class:`PlannerPromptMissing`
(fail closed); there is no built-in fallback prompt.

The model answers with :class:`PlannerOutput` through the existing
``ObservableLLM`` structured-output chain (Backboard in production).
``PlannedTurn`` is deliberately not the LLM schema: ``llm_tokens`` and
``llm_cost_usd`` come from the provider's usage data, never from the model.

Usage and cost:

* Tokens come from the provider message's ``usage_metadata`` (ChatBackboard
  fills it from Backboard's ``input_tokens`` / ``output_tokens`` /
  ``total_tokens``; a structured-output repair re-ask is summed in).
* When the provider reports nothing, tokens are ESTIMATED conservatively as
  ``ceil(chars / 3)`` of the prompt, input and output text, and the turn is
  logged with ``usage_estimated=true``. That estimate cannot see a hidden
  repair re-ask.
* Backboard reports no price, so USD = tokens x the per-1k rates in settings
  (``planner_usd_per_1k_input_tokens`` / ``_output_tokens``, set high on
  purpose). Tokens the provider reports beyond input + output are priced at
  the output rate.

The prompt version (sha256 of the prompt text) is logged on every turn
(``planner_turn`` / guard-rail events, field ``prompt_sha256``) and prefixed
to ``PlannedTurn.intent_note``.

Target replies are passed to the model as JSON data inside the user message.
They are untrusted; the security owner's prompt must treat them as data.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from langchain_core.runnables import Runnable, RunnableLambda
from pydantic import BaseModel, ConfigDict, Field

from cyberredteam.engine.types import ConversationState, PlannedTurn
from cyberredteam.llm.observable import ObservableLLM
from cyberredteam.logging import log_event
from cyberredteam.observability.hooks import trace_op
from cyberredteam.planners.errors import (
    PlannerInvalidOutput,
    PlannerPromptMissing,
    PlannerRefused,
    ScopeClassifierMissing,
)
from cyberredteam.planners.guards import (
    DenyCategoryChecker,
    GuardRails,
    ScopeClassifier,
    default_deny_checker,
    looks_like_refusal,
)
from cyberredteam.settings import get_settings

logger = logging.getLogger("cyberredteam.planners")

PLANNER_KIND = "llm"
# prompts/ sits at the project root: .../src/cyberredteam/planners/llm_planner.py -> parents[3]
DEFAULT_PROMPT_PATH = Path(__file__).resolve().parents[3] / "prompts" / "planner.md"
CHARS_PER_TOKEN_ESTIMATE = 3
INTENT_NOTE_MAX_CHARS = 500


class PlannerOutput(BaseModel):
    """What the planner model returns. It has no usage fields: usage comes
    from the provider. Unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    message: str = Field(default="", description="The next user message to send to the target.")
    intent_note: str = Field(default="", description="One short sentence on what this turn tests.")
    end_conversation: bool = Field(
        default=False, description="True to end the conversation now; message is then not sent."
    )
    refused: bool = Field(
        default=False, description="True if you will not produce this turn for policy reasons."
    )
    refusal_reason: str | None = Field(
        default=None, description="Only when refused: the policy category that applies."
    )


# ── Prompt ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PlannerPrompt:
    text: str
    sha256: str
    source: str

    @classmethod
    def from_text(cls, text: str, source: str = "<injected>") -> "PlannerPrompt":
        if not text or not text.strip():
            raise PlannerPromptMissing(_missing_message(source, "empty"))
        return cls(text=text, sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(), source=source)


def _missing_message(source: str, problem: str) -> str:
    return (
        f"LLMPlanner cannot start: planner system prompt {source} is {problem}. "
        "prompts/planner.md is owned and reviewed by the security owner and is not "
        "shipped with the code; ask them to supply it, or use the scripted planner."
    )


def default_prompt_path() -> Path:
    configured = get_settings().planner_prompt_path
    return Path(configured) if configured else DEFAULT_PROMPT_PATH


def load_planner_prompt(path: Path | str | None = None) -> PlannerPrompt:
    """Read the planner prompt. Missing, unreadable or blank: fail closed."""
    p = Path(path) if path is not None else default_prompt_path()
    if not p.is_file():
        raise PlannerPromptMissing(_missing_message(str(p), "missing"))
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlannerPromptMissing(_missing_message(str(p), f"unreadable ({type(exc).__name__})")) from None
    return PlannerPrompt.from_text(text, source=str(p))


# ── Usage ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PlannerUsage:
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated: bool

    def cost_usd(self, usd_per_1k_input: float, usd_per_1k_output: float) -> float:
        extra = max(0, self.total_tokens - self.input_tokens - self.output_tokens)
        return (
            self.input_tokens * usd_per_1k_input + (self.output_tokens + extra) * usd_per_1k_output
        ) / 1000.0


def usage_from_provider(raw: Any) -> PlannerUsage | None:
    """Read LangChain ``usage_metadata`` from the provider's raw message."""
    meta = getattr(raw, "usage_metadata", None)
    if not isinstance(meta, dict) or not meta:
        return None
    try:
        i = max(0, int(meta.get("input_tokens") or 0))
        o = max(0, int(meta.get("output_tokens") or 0))
        t = max(i + o, int(meta.get("total_tokens") or 0))
    except (TypeError, ValueError):
        return None
    if t <= 0:
        return None
    return PlannerUsage(input_tokens=i, output_tokens=o, total_tokens=t, estimated=False)


def estimate_usage(input_text: str, output_text: str) -> PlannerUsage:
    i = math.ceil(len(input_text) / CHARS_PER_TOKEN_ESTIMATE)
    o = math.ceil(len(output_text) / CHARS_PER_TOKEN_ESTIMATE)
    return PlannerUsage(input_tokens=i, output_tokens=o, total_tokens=i + o, estimated=True)


# ── Planner ──────────────────────────────────────────────────────────────────


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


class LLMPlanner:
    """Model-driven planner for one conversation of ``technique``.

    ``system_prompt`` (tests) overrides reading ``prompt_path``. A scope
    classifier is mandatory. ``llm`` defaults to the ``planner`` role client.
    """

    def __init__(
        self,
        technique: str,
        *,
        scope_classifier: ScopeClassifier | None,
        llm: ObservableLLM | None = None,
        system_prompt: str | None = None,
        prompt_path: Path | str | None = None,
        prompt: PlannerPrompt | None = None,
        max_message_chars: int | None = None,
        deny_checker: DenyCategoryChecker | None = None,
        usd_per_1k_input_tokens: float | None = None,
        usd_per_1k_output_tokens: float | None = None,
        transcript_chars_per_turn: int | None = None,
    ) -> None:
        if prompt is None:
            prompt = (
                PlannerPrompt.from_text(system_prompt)
                if system_prompt is not None
                else load_planner_prompt(prompt_path)
            )
        if scope_classifier is None:
            raise ScopeClassifierMissing(
                "LLMPlanner needs a technique-scope classifier and refuses to run without one"
            )
        settings = get_settings()
        self.technique = technique
        self.prompt = prompt
        self.guards = GuardRails(
            max_message_chars=max_message_chars or settings.planner_max_message_chars,
            deny_checker=deny_checker or default_deny_checker(),
            scope_classifier=scope_classifier,
            check_refusal_text=True,
        )
        self.usd_in = (
            settings.planner_usd_per_1k_input_tokens if usd_per_1k_input_tokens is None else usd_per_1k_input_tokens
        )
        self.usd_out = (
            settings.planner_usd_per_1k_output_tokens if usd_per_1k_output_tokens is None else usd_per_1k_output_tokens
        )
        self.transcript_chars = transcript_chars_per_turn or settings.planner_transcript_chars_per_turn
        if llm is None:
            from cyberredteam.llm.factory import get_llm_for_agent

            llm = get_llm_for_agent("planner")
        self.llm = llm
        self._chain: Runnable = llm.build_structured_chain(prompt.text, PlannerOutput)

    @property
    def prompt_version(self) -> str:
        return self.prompt.sha256

    # ── Model call (runs in a worker thread) ─────────────────────────────────

    def build_user_message(self, state: ConversationState) -> str:
        transcript = [
            {
                "index": t.index,
                "message": t.message,
                "response": _truncate(t.response_text, self.transcript_chars),
                "target_error": t.error is not None,
                "monitor_hits": list(t.monitor_hits),
            }
            for t in state.turns
        ]
        payload = {
            "technique": state.technique,
            "trial_index": state.trial_index,
            "max_turns": state.max_turns,
            "remaining_turns": state.remaining_turns,
            "monitor_hits": list(state.monitor_hits),
            "transcript": transcript,
        }
        return json.dumps(payload, ensure_ascii=False)

    def _invoke(self, user_message: str) -> tuple[PlannerOutput, PlannerUsage]:
        captured: dict[str, Any] = {}

        def capture(result: Any) -> Any:
            captured["result"] = result
            return result

        chain = self._chain | RunnableLambda(capture)
        parsed = self.llm.invoke_chain(chain, user_message, system_context=self.prompt.text)
        output = parsed if isinstance(parsed, PlannerOutput) else PlannerOutput.model_validate(parsed)

        result = captured.get("result")
        raw = result.get("raw") if isinstance(result, dict) else None
        usage = usage_from_provider(raw)
        if usage is None:
            out_text = str(getattr(raw, "content", "") or "") or output.model_dump_json()
            usage = estimate_usage(self.prompt.text + user_message, out_text)
        return output, usage

    # ── TurnPlanner ──────────────────────────────────────────────────────────

    @trace_op("planner.llm.next_turn")
    async def next_turn(self, state: ConversationState) -> PlannedTurn | None:
        user_message = self.build_user_message(state)
        output, usage = await asyncio.to_thread(self._invoke, user_message)
        tokens = usage.total_tokens
        cost = usage.cost_usd(self.usd_in, self.usd_out)
        ctx: dict[str, Any] = {
            "planner": PLANNER_KIND,
            "technique": self.technique,
            "conversation_id": state.conversation_id,
            "llm_tokens": tokens,
            "llm_cost_usd": cost,
            "prompt_sha256": self.prompt_version,
            "usage_estimated": usage.estimated,
        }

        # 1. Refusal: structural flag first, then the conservative text check
        #    on the note (the message is text-checked inside the guard chain).
        if output.refused:
            raise self.guards.stop(PlannerRefused, detail="structural", **ctx)
        if looks_like_refusal(output.intent_note) or (
            output.end_conversation and looks_like_refusal(output.message)
        ):
            raise self.guards.stop(PlannerRefused, detail="refusal_text", **ctx)

        note = _truncate(f"[planner_prompt_sha256={self.prompt_version}] {output.intent_note}".strip(),
                         INTENT_NOTE_MAX_CHARS)
        if output.end_conversation:
            log_event(logger, "planner_turn", action="end_conversation", **ctx)
            return PlannedTurn(end_conversation=True, intent_note=note, llm_tokens=tokens, llm_cost_usd=cost)

        if not output.message.strip():
            raise self.guards.stop(PlannerInvalidOutput, detail="empty_message", **ctx)

        # 2-4. Refusal text, length cap (reject), deny categories, scope.
        self.guards.check(
            output.message,
            planner=PLANNER_KIND,
            technique=self.technique,
            conversation_id=state.conversation_id,
            llm_tokens=tokens,
            llm_cost_usd=cost,
            prompt_sha256=self.prompt_version,
            usage_estimated=usage.estimated,
        )
        log_event(logger, "planner_turn", action="send", message_chars=len(output.message), **ctx)
        return PlannedTurn(message=output.message, intent_note=note, llm_tokens=tokens, llm_cost_usd=cost)


__all__ = [
    "DEFAULT_PROMPT_PATH",
    "LLMPlanner",
    "PLANNER_KIND",
    "PlannerOutput",
    "PlannerPrompt",
    "PlannerUsage",
    "default_prompt_path",
    "estimate_usage",
    "load_planner_prompt",
    "usage_from_provider",
]
