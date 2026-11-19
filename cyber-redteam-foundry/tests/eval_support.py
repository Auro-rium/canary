"""Shared helpers for the WP5 evaluation tests (not collected by pytest)."""

from __future__ import annotations

import itertools
import threading
import uuid
from collections.abc import Callable
from typing import Any

from fixtures.fake_target import FakeTarget

from cyberredteam.contracts import Conversation, JudgeVote, ToolCallObservation, Turn
from cyberredteam.engine.types import MonitorContext
from cyberredteam.evaluation.judge import JudgeVoteOutput
from cyberredteam.evaluation.verdict import JudgeOutcome


def context(canaries=(), forbidden=(), allow_destructive=False) -> MonitorContext:
    return MonitorContext(
        campaign_id="c1",
        conversation_id="conv1",
        technique="prompt_injection",
        target=FakeTarget().target_config(),
        canary_values=tuple(canaries),
        forbidden_tools=frozenset(forbidden),
        allow_destructive_tools=allow_destructive,
    )


def turn(response: str = "ok", message: str = "hello", index: int = 0, tools=(), hits=(),
         conversation_id: str = "conv1") -> Turn:
    return Turn(
        conversation_id=conversation_id,
        index=index,
        message=message,
        response_text=response,
        tool_calls=[
            t if isinstance(t, ToolCallObservation) else ToolCallObservation(name=t)
            for t in tools
        ],
        http_status=200,
        latency_ms=1.0,
        monitor_hits=list(hits),
    )


_TRIALS = itertools.count()


def conversation(replies: list[str] | None = None, hits: list[list[str]] | None = None,
                 tools: list[list] | None = None, technique: str = "prompt_injection",
                 campaign_id: str = "camp1", conversation_id: str | None = None) -> Conversation:
    cid = conversation_id or str(uuid.uuid4())
    replies = replies if replies is not None else ["Sure, happy to help."]
    turns = [
        turn(
            response=r,
            message=f"benign test message {i}",
            index=i,
            tools=(tools[i] if tools else ()),
            hits=(hits[i] if hits else ()),
            conversation_id=cid,
        )
        for i, r in enumerate(replies)
    ]
    return Conversation(
        conversation_id=cid, campaign_id=campaign_id, technique=technique,
        trial_index=next(_TRIALS), status="completed", turns=turns,
    )


def vote(i: int, judgement: str, confidence: float = 0.9, first: int | None = None,
         severity: str = "high") -> JudgeVote:
    return JudgeVote(vote_index=i, judgement=judgement, confidence=confidence,
                     first_failing_turn=first, severity=severity, rationale=f"vote {i}")


def outcome(*judgements: str, valid: list[bool] | None = None, first: int | None = None,
            confidence: float = 0.9) -> JudgeOutcome:
    votes = [vote(i, j, confidence=confidence, first=first if j == "unsafe" else None)
             for i, j in enumerate(judgements)]
    return JudgeOutcome(votes=votes, valid=valid or [True] * len(votes), k=len(votes))


Responder = Callable[[str, int], Any]


class FakeJudgeLLM:
    """Stands in for ObservableLLM. ``responder(user_message, call_number)``
    returns a ``JudgeVoteOutput``/dict, or raises."""

    deployment = "fake/judge"

    def __init__(self, responder: Responder) -> None:
        self.responder = responder
        self.messages: list[str] = []
        self.system_prompts: list[str] = []
        self._lock = threading.Lock()
        self._n = 0

    def build_structured_chain(self, system_prompt, schema):
        assert schema is JudgeVoteOutput
        self.system_prompts.append(system_prompt)
        return object()

    def invoke_chain(self, chain, user_message, system_context="", run_id=None):
        with self._lock:
            n = self._n
            self._n += 1
            self.messages.append(user_message)
        return self.responder(user_message, n)


def fixed(*outputs: Any) -> Responder:
    """Responder returning ``outputs[n]`` (exceptions are raised)."""

    def respond(_msg: str, n: int) -> Any:
        out = outputs[n % len(outputs)]
        if isinstance(out, BaseException):
            raise out
        return out

    return respond


def out(judgement: str, confidence: float = 0.9, first: int | None = None, **kw) -> JudgeVoteOutput:
    return JudgeVoteOutput(judgement=judgement, confidence=confidence, first_failing_turn=first, **kw)


def transcript_rule_judge(msg: str, n: int) -> JudgeVoteOutput:
    """A benign rule-based fake judge: unsafe if a CANARY- marker or the fake
    forbidden tool shows up in the transcript block."""
    block = msg.split("<<<BEGIN", 1)[1]
    if "CANARY-" in block or '"delete_record"' in block:
        return out("unsafe", 0.9, first=0)
    return out("safe", 0.9)
