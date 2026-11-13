"""Engine seams (WP3): planner, monitor, event sink and on-call protocols.

The engine only defines these interfaces. Real planners are WP4 (their message
content is owned by the security owner and is out of scope here); real
detectors and the judge are WP5; durable event delivery is WP7/WP8.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyberredteam.contracts import Severity, SseEventType, TargetConfig, Turn

# Namespace for deterministic conversation ids (resume relies on them).
_CONVERSATION_NS = uuid.UUID("6f1c2b9e-3d4a-5b6c-8d7e-9f0a1b2c3d4e")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ── Conversation identity ────────────────────────────────────────────────────


class ConversationSpec(_Model):
    """One conversation the campaign must run: a technique and a trial index."""

    campaign_id: str
    technique: str
    trial_index: int = Field(ge=0)

    @property
    def conversation_id(self) -> str:
        """Deterministic id: re-running a campaign finds the same conversations."""
        key = f"{self.campaign_id}\x1f{self.technique}\x1f{self.trial_index}"
        return str(uuid.uuid5(_CONVERSATION_NS, key))


# ── Planner (WP4 implements) ─────────────────────────────────────────────────


class PlannedTurn(_Model):
    """The planner's next message.

    ``end_conversation=True`` ends the conversation without sending
    ``message`` (which may then be empty). ``llm_tokens`` / ``llm_cost_usd``
    report what producing this turn cost so the engine can charge the
    campaign budget (0 for scripted planners). Planners must fill them from
    the provider's usage data, never from model output.
    """

    message: str = ""
    intent_note: str = ""
    end_conversation: bool = False
    llm_tokens: int = Field(default=0, ge=0)
    llm_cost_usd: float = Field(default=0.0, ge=0)

    @model_validator(mode="after")
    def _message_required_unless_ending(self) -> "PlannedTurn":
        if not self.end_conversation and not self.message.strip():
            raise ValueError("message must be non-empty unless end_conversation is true")
        return self


class ConversationState(_Model):
    """What a planner sees before each turn. ``turns`` is the raw transcript."""

    campaign_id: str
    conversation_id: str
    technique: str
    trial_index: int
    turns: list[Turn] = Field(default_factory=list)
    monitor_hits: list[str] = Field(default_factory=list)
    max_turns: int
    remaining_turns: int = Field(ge=0)


@runtime_checkable
class TurnPlanner(Protocol):
    async def next_turn(self, state: ConversationState) -> PlannedTurn | None:
        """Return the next message, or ``None`` to end the conversation."""
        ...


PlannerFactory = Callable[[ConversationSpec], TurnPlanner]


# ── Monitors (WP5 extends) ───────────────────────────────────────────────────


class MonitorHit(_Model):
    name: str = Field(min_length=1)
    severity: Severity = "medium"


class MonitorResult(_Model):
    hits: list[MonitorHit] = Field(default_factory=list)
    stop: bool = False
    critical: bool = False


@dataclass(frozen=True)
class MonitorContext:
    """Per-campaign safety inputs. These are not part of ``TargetConfig``, so
    the caller (WP7/WP8) supplies them through :class:`EngineDeps`."""

    campaign_id: str
    conversation_id: str
    technique: str
    target: TargetConfig
    canary_values: tuple[str, ...] = ()
    forbidden_tools: frozenset[str] = frozenset()
    allow_destructive_tools: bool = False


@runtime_checkable
class TurnMonitor(Protocol):
    async def check(self, turn: Turn, context: MonitorContext) -> MonitorResult: ...


# ── Events and alerts ────────────────────────────────────────────────────────


@runtime_checkable
class EventSink(Protocol):
    async def emit(self, event_type: SseEventType, payload: BaseModel) -> None:
        """Publish one SSE v2 event. The sink assigns ``seq`` and the timestamp."""
        ...


@dataclass
class CollectingEventSink:
    """In-memory sink (tests and dev). Each entry is ``(type, payload)``."""

    events: list[tuple[str, BaseModel]] = field(default_factory=list)

    async def emit(self, event_type: SseEventType, payload: BaseModel) -> None:
        self.events.append((event_type, payload))

    def of_type(self, event_type: str) -> list[BaseModel]:
        return [p for t, p in self.events if t == event_type]


class NullEventSink:
    async def emit(self, event_type: SseEventType, payload: BaseModel) -> None:
        return None


class OnCallAlert(_Model):
    """Sent to the target's on-call hook on a critical monitor hit. Carries ids
    and hit names only, never evidence text."""

    campaign_id: str
    conversation_id: str
    target_id: str
    environment: str
    turn_index: int
    hits: list[str]


OnCallNotifier = Callable[[OnCallAlert], Awaitable[None]]
