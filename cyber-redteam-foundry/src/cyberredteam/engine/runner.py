"""Conversation engine (WP3): bounded multi-turn loop and campaign fan-out.

Per turn (plan section 3/WP3):

0. ``RunControl.check`` (cancel / kill switch; fails closed) and the budget check
1. ``planner.next_turn(state)``: a message, or ``None`` to end
2. ``RunControl.check`` again, then ``SessionAdapter.send``. *Every* HTTP
   request inside the send (attempts, retries, auth sub-requests) first passes
   the adapter's ``before_attempt`` hook, which re-checks RunControl and
   charges one request to the :class:`BudgetLedger`; a refusal aborts the send.
   While the send is in flight a watcher polls RunControl and calls
   ``adapter.cancel()``, which also interrupts retry / Retry-After waits.
3. every ``TurnMonitor.check``. A critical hit fires the metrics alert at once.
4. ``ConversationRepo.append_turn``; on a monitor stop the terminal
   ``stopped_monitor`` status is persisted right after it (even if the append
   failed), then the on-call hook is notified, all before any event.
5. SSE ``turn`` (plus ``monitor_hit`` / ``budget_update``) events

Stop conditions and the resulting ``ConversationStatus``:

=============================  ===============================
max_turns / planner ends       ``completed``
monitor stop (critical or not) ``stopped_monitor``
budget exhausted               ``stopped_budget``
campaign cancelled             ``cancelled``
global kill switch             ``stopped_killed``
3+ target errors in a row      ``stopped_target_error_streak``
planner guard-rail stop        ``stopped_planner_guardrail``
planner/monitor exception      ``error``
=============================  ===============================

A planner guard-rail stop (``PlannerGuardrailStop``) also charges its
``llm_tokens`` / ``llm_cost_usd`` to the budget. A campaign-fatal planner
configuration error (``campaign_fatal``) ends that conversation ``error`` and
then fails the whole campaign once.

Evaluation (WP5): after each conversation reaches a terminal status (except
``cancelled`` / ``stopped_killed``, or with no turns) ``EngineDeps.evaluator``
is awaited with the conversation id, the ``verdict`` event is emitted and a
``confirmed`` verdict sets ``stop_on_first_confirmed``. At campaign end
``EngineDeps.aggregate_results`` supplies ``campaign_complete.confirmed`` and
the technique results.

Resume: conversation ids are deterministic (:attr:`ConversationSpec.conversation_id`).
Re-running a campaign skips conversations in a terminal status and continues a
``running`` one from its persisted turns. Before continuing, the monitors are
re-run on the last persisted turn: if they stop (e.g. a critical hit whose
status write was lost), the conversation is closed as ``stopped_monitor``
(alert and on-call fire again) and nothing is sent. A task cancellation
(worker shutdown) leaves a conversation ``running`` unless a terminal status
was already persisted; any other exception marks it ``error``.

RunControl, the event sink and the on-call hook are each bounded by
``EngineDeps.hook_timeout_s`` (env ``CANARY_ENGINE_HOOK_TIMEOUT_S``, default
5 s). A RunControl failure or timeout counts as ``killed``.

The repositories are synchronous; their calls are short single transactions
and run on the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, get_args

from pydantic import BaseModel, SecretStr

from cyberredteam.contracts import (
    TERMINAL_CONVERSATION_STATUSES,
    CampaignCancelledPayload,
    CampaignCompletePayload,
    CampaignFailedPayload,
    CampaignPolicy,
    CampaignRequest,
    CampaignStartedPayload,
    Conversation,
    ConversationFinishedPayload,
    ConversationStartedPayload,
    ConversationStatus,
    MonitorHitPayload,
    Severity,
    SseEventType,
    TargetConfig,
    Turn,
    TurnPayload,
    VerdictPayload,
    normalize_technique,
)
from cyberredteam.engine.budget import BudgetLedger
from cyberredteam.engine.control import RunControl
from cyberredteam.engine.monitors import BuiltinSafetyMonitor
from cyberredteam.engine.types import (
    CampaignAggregate,
    CampaignAggregator,
    ConversationEvaluator,
    ConversationSpec,
    ConversationState,
    EventSink,
    MonitorContext,
    MonitorHit,
    MonitorResult,
    NullEventSink,
    OnCallAlert,
    OnCallNotifier,
    PlannedTurn,
    PlannerFactory,
    TurnMonitor,
    TurnPlanner,
)
from cyberredteam.observability.hooks import get_metrics, trace_op
from cyberredteam.storage.v2.redaction import redact
from cyberredteam.storage.v2.repositories import BudgetLedgerRepo, CampaignRepo, ConversationRepo
from cyberredteam.transport.rate_limit import InProcessTokenBucket, RateLimiter
from cyberredteam.transport.session_adapter import SendAborted, SessionAdapter, TurnResult

logger = logging.getLogger(__name__)

ERROR_STREAK_LIMIT = 3
RESUME_ACTOR = "system:engine-resume"
HOOK_TIMEOUT_ENV = "CANARY_ENGINE_HOOK_TIMEOUT_S"
DEFAULT_HOOK_TIMEOUT_S = 5.0
MAX_HOOK_TIMEOUT_S = 60.0
MIN_CONTROL_POLL_S = 0.05
MAX_CONTROL_POLL_S = 60.0
MAX_STEP_TIMEOUT_S = 600.0

BeforeAttempt = Callable[[], Awaitable[None]]
AdapterFactory = Callable[[TargetConfig, str, RateLimiter, BeforeAttempt], SessionAdapter]
LimiterFactory = Callable[[TargetConfig, CampaignPolicy], RateLimiter]

_SIGNAL_STATUS: dict[str, ConversationStatus] = {
    "killed": "stopped_killed",
    "cancelled": "cancelled",
}


_SEVERITIES = frozenset(get_args(Severity))


class CampaignRefused(ValueError):
    """The engine refuses to start: unverified target or a production-policy violation."""


def default_adapter_factory(
    target: TargetConfig, campaign_id: str, limiter: RateLimiter, before_attempt: BeforeAttempt
) -> SessionAdapter:
    return SessionAdapter(
        target, campaign_id=campaign_id, rate_limiter=limiter, before_attempt=before_attempt
    )


def _default_monitors() -> list[TurnMonitor]:
    return [BuiltinSafetyMonitor()]


def _default_hook_timeout() -> float:
    """From env, finite and clamped to (0, 60]; anything invalid gives the default."""
    try:
        value = float(os.environ.get(HOOK_TIMEOUT_ENV, DEFAULT_HOOK_TIMEOUT_S))
    except ValueError:
        return DEFAULT_HOOK_TIMEOUT_S
    if not math.isfinite(value) or value <= 0:
        return DEFAULT_HOOK_TIMEOUT_S
    return min(value, MAX_HOOK_TIMEOUT_S)


def _finite_positive(name: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    v = float(value)
    if not math.isfinite(v) or v <= 0:
        raise ValueError(f"{name} must be finite and > 0")
    return v


def _bounded_timing(name: str, value: object) -> float:
    """Validate an EngineDeps timing knob: finite, > 0, clamped to its range."""
    v = _finite_positive(name, value)
    if name == "control_poll_s":
        return min(max(v, MIN_CONTROL_POLL_S), MAX_CONTROL_POLL_S)
    if name == "hook_timeout_s":
        return min(v, MAX_HOOK_TIMEOUT_S)
    return min(v, MAX_STEP_TIMEOUT_S)


_TIMING_FIELDS = frozenset(
    {"hook_timeout_s", "control_poll_s", "planner_timeout_s", "monitor_timeout_s", "evaluation_timeout_s"}
)


def _genuinely_cancelled() -> bool:
    """True if this task was really cancelled (worker shutdown), as opposed to
    a hook raising ``CancelledError`` on its own."""
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


@dataclass
class EngineRepos:
    conversations: ConversationRepo
    campaigns: CampaignRepo
    budget: BudgetLedgerRepo


@dataclass
class EngineDeps:
    """Everything the engine needs, injected (WP7 builds one per campaign run).

    ``canary_values``, ``forbidden_tools`` and ``on_call`` are per-target safety
    inputs that ``TargetConfig`` does not carry. The limiter is
    ``rate_limiter`` if given, else ``limiter_factory(target, policy)`` (WP7's
    shared per-target limiter), else an in-process bucket from
    ``policy.rate_limit_rps``. The adapter factory must pass
    ``before_attempt`` to the ``SessionAdapter``: it is how budget and
    cancel/kill are enforced per HTTP request.
    """

    repos: EngineRepos
    planner_factory: PlannerFactory
    run_control: RunControl
    adapter_factory: AdapterFactory = default_adapter_factory
    monitors: Sequence[TurnMonitor] = field(default_factory=_default_monitors)
    events: EventSink = field(default_factory=NullEventSink)
    rate_limiter: RateLimiter | None = None
    limiter_factory: LimiterFactory | None = None
    clock: Callable[[], float] = time.monotonic
    canary_values: tuple[str, ...] = ()
    forbidden_tools: frozenset[str] = frozenset()
    on_call: OnCallNotifier | None = None
    # WP5 evaluation (wired by the worker): judge each finished conversation and
    # aggregate technique results at campaign end. None = no evaluation.
    evaluator: ConversationEvaluator | None = None
    aggregate_results: CampaignAggregator | None = None
    evaluation_timeout_s: float = 300.0
    hook_timeout_s: float = field(default_factory=_default_hook_timeout)
    control_poll_s: float = 1.0
    planner_timeout_s: float = 120.0
    monitor_timeout_s: float = 30.0

    def __setattr__(self, name: str, value: object) -> None:
        # Timing knobs are validated on construction and on later assignment:
        # finite and > 0 (an infinite timeout lets a hanging hook block forever),
        # hook timeout <= 60 s, poll interval floored at 0.05 s (no spin loop).
        if name in _TIMING_FIELDS:
            value = _bounded_timing(name, value)
        super().__setattr__(name, value)


class ConversationResult(BaseModel):
    conversation_id: str
    technique: str
    trial_index: int
    status: ConversationStatus
    turns: int
    resumed: bool = False
    skipped: bool = False


CampaignOutcomeStatus = Literal["completed", "cancelled", "killed"]


class CampaignOutcome(BaseModel):
    campaign_id: str
    status: CampaignOutcomeStatus
    conversations: list[ConversationResult]
    requests_used: int
    llm_cost_usd: float
    duration_seconds: float

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.conversations if c.skipped)


@dataclass
class CampaignRuntime:
    """Shared state of one campaign run (not serialisable; never put in graph state)."""

    request: CampaignRequest
    campaign_id: str
    deps: EngineDeps
    ledger: BudgetLedger
    limiter: RateLimiter
    turns_total: int = 0
    monitor_hits_total: int = 0
    # Set by a confirmed verdict when policy.stop_on_first_confirmed: conversations
    # not started yet are skipped and running ones end at their next turn.
    stop_requested: bool = False

    @classmethod
    def create(cls, request: CampaignRequest, campaign_id: str, deps: EngineDeps) -> CampaignRuntime:
        limiter = deps.rate_limiter
        if limiter is None and deps.limiter_factory is not None:
            limiter = deps.limiter_factory(request.target, request.policy)
        if limiter is None:
            limiter = InProcessTokenBucket(request.policy.rate_limit_rps)
        ledger = BudgetLedger(campaign_id, request.policy, deps.repos.budget)
        return cls(request=request, campaign_id=campaign_id, deps=deps, ledger=ledger, limiter=limiter)


def plan_conversations(request: CampaignRequest, campaign_id: str) -> list[ConversationSpec]:
    """Deterministic strategist: every technique x every trial, never truncated."""
    return [
        ConversationSpec(campaign_id=campaign_id, technique=t, trial_index=i)
        for t in request.policy.techniques
        for i in range(request.policy.trials_per_technique)
    ]


# ── Bounded hooks ────────────────────────────────────────────────────────────


async def _emit(deps: EngineDeps, event_type: SseEventType, payload: BaseModel) -> None:
    try:
        async with asyncio.timeout(deps.hook_timeout_s):
            await deps.events.emit(event_type, payload)
    except asyncio.CancelledError:
        if _genuinely_cancelled():
            raise
        logger.warning("event sink raised CancelledError for %s", event_type)
    except Exception:  # an event sink (or its timeout) must never break the run
        logger.warning("event sink failed for %s", event_type)


async def _control(deps: EngineDeps, campaign_id: str) -> str | None:
    """``None``, ``"cancelled"`` or ``"killed"``. Fails closed: an error, a
    timeout, a hook-raised CancelledError or any unknown value means killed."""
    try:
        async with asyncio.timeout(deps.hook_timeout_s):
            signal = await deps.run_control.check(campaign_id)
    except asyncio.CancelledError:
        if _genuinely_cancelled():
            raise
        logger.error("run control raised CancelledError for %s; treating as killed", campaign_id)
        return "killed"
    except Exception:  # fail closed, timeouts included
        logger.error("run control check failed for %s; treating as killed", campaign_id)
        return "killed"
    # Exact plain strings only (no subclasses / __eq__ tricks); return literals.
    if signal is None:
        return None
    if type(signal) is str and signal == "cancelled":
        return "cancelled"
    if not (type(signal) is str and signal == "killed"):
        logger.error("unknown run control signal for %s; treating as killed", campaign_id)
    return "killed"


def _safe_metrics(call: Callable[[], None]) -> None:
    try:
        call()
    except Exception:
        logger.warning("metrics hook failed", exc_info=True)


def _history_from(turns: list[Turn]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for t in turns:
        if t.error is None:
            out.append({"role": "user", "content": t.message})
            out.append({"role": "assistant", "content": t.response_text})
    return out


def _trailing_errors(turns: list[Turn]) -> int:
    n = 0
    for t in reversed(turns):
        if t.error is None:
            break
        n += 1
    return n


@trace_op("engine.planner")
async def _plan(planner: TurnPlanner, state: ConversationState) -> PlannedTurn | None:
    return await planner.next_turn(state)


@trace_op("engine.monitor")
async def _monitor(monitor: TurnMonitor, turn: Turn, context: MonitorContext) -> MonitorResult:
    return await monitor.check(turn, context)


# Conversations that never reach the judge: an operator stop must not spend more
# LLM budget, and a conversation without turns has nothing to judge.
_NO_EVALUATION = frozenset({"cancelled", "stopped_killed"})


_MIN_SECRET_CHARS = 4  # same floor as EventLogSink: shorter values would mangle ordinary text


def _masked_values(runtime: CampaignRuntime) -> tuple[str, ...]:
    """Exact strings to mask in anything shown to viewers: the target's canaries
    plus its own auth secrets (>= 4 chars)."""
    secrets: list[str] = []
    for _, value in getattr(runtime.request.target, "auth", None) or ():
        if isinstance(value, SecretStr):
            revealed = value.get_secret_value()
            if len(revealed) >= _MIN_SECRET_CHARS:
                secrets.append(revealed)
    return (*runtime.deps.canary_values, *secrets)


async def _charge_judge(runtime: CampaignRuntime) -> None:
    """Charge the judge's provider-reported usage (if the evaluator tracks it) to the ledger."""
    take = getattr(runtime.deps.evaluator, "take_judge_usage", None)
    if take is None:
        return
    try:
        tokens, usd = take()
        await runtime.ledger.charge_llm(tokens, usd)
    except Exception as exc:
        logger.error("judge usage charge failed (%s)", type(exc).__name__)


async def _evaluate(runtime: CampaignRuntime, cid: str, status: ConversationStatus, n_turns: int) -> None:
    """Judge a finished conversation, emit the ``verdict`` event and honour
    ``stop_on_first_confirmed``. Never raises (except a genuine cancellation):
    the evaluator itself turns judge failures into an ``inconclusive`` verdict,
    and anything that still escapes is logged (no verdict is stored; a missing
    verdict is never read as ``safe``)."""
    deps = runtime.deps
    if deps.evaluator is None or n_turns == 0 or status in _NO_EVALUATION:
        return
    if await _control(deps, runtime.campaign_id):
        return  # cancelled or killed meanwhile: spend nothing more
    try:
        async with asyncio.timeout(deps.evaluation_timeout_s):
            verdict = await deps.evaluator(cid)
    except asyncio.CancelledError:
        if _genuinely_cancelled():
            raise
        logger.error("evaluation of %s raised CancelledError", cid)
        await _charge_judge(runtime)
        return
    except Exception as exc:  # incl. the timeout
        logger.error("evaluation of %s failed: %s", cid, type(exc).__name__)
        await _charge_judge(runtime)
        return
    await _charge_judge(runtime)
    if verdict is None:
        return
    try:
        # The judge read the raw transcript and may quote a canary in its
        # rationales: redact them like the turn previews before they reach the event log.
        canaries = _masked_values(runtime)
        shown = verdict.model_copy(update={
            "rationale": redact(verdict.rationale, canaries).text,
            "judge_votes": [
                v.model_copy(update={"rationale": redact(v.rationale, canaries).text})
                for v in verdict.judge_votes
            ],
        })
        payload = VerdictPayload(campaign_id=runtime.campaign_id, verdict=shown)
    except Exception:
        logger.error("verdict payload for %s invalid", cid)
        return
    await _emit(deps, "verdict", payload)
    if verdict.verdict == "confirmed" and runtime.request.policy.stop_on_first_confirmed:
        runtime.stop_requested = True


# ── Conversation ─────────────────────────────────────────────────────────────


@dataclass
class _Conv:
    spec: ConversationSpec
    planner: TurnPlanner | None
    context: MonitorContext
    turns: list[Turn]
    session_ref: str | None
    error_streak: int
    adapter: SessionAdapter | None = None
    # Why the current send was refused (budget / cancel / kill), if it was.
    abort: ConversationStatus | None = None
    # A terminal status already written to the DB (never overwritten).
    persisted_status: ConversationStatus | None = None


async def _run_monitors(runtime: CampaignRuntime, context: MonitorContext, turn: Turn) -> MonitorResult:
    hits: list[MonitorHit] = []
    stop = critical = False
    for monitor in runtime.deps.monitors:
        try:
            async with asyncio.timeout(runtime.deps.monitor_timeout_s):
                res = await _monitor(monitor, turn, context)
            # Read and check every field here, so a malformed result is a
            # monitor error (turn still recorded), never a lost turn.
            if not isinstance(res, MonitorResult):
                raise TypeError("monitor returned a non-MonitorResult")
            res_hits = list(res.hits)
            res_stop, res_critical = res.stop, res.critical
            if type(res_stop) is not bool or type(res_critical) is not bool:
                raise TypeError("monitor stop/critical must be booleans")
            for h in res_hits:
                if (
                    not isinstance(h, MonitorHit)
                    or type(h.name) is not str
                    or not h.name
                    or type(h.severity) is not str
                    or h.severity not in _SEVERITIES
                ):
                    raise TypeError("monitor returned a malformed hit")
        except (Exception, asyncio.CancelledError) as exc:
            if isinstance(exc, asyncio.CancelledError) and _genuinely_cancelled():
                raise
            # Fail closed: a broken, hanging or self-cancelling detector stops the conversation.
            logger.error("monitor %s failed (%s)", type(monitor).__name__, type(exc).__name__)
            hits.append(MonitorHit(name=f"monitor_error:{type(monitor).__name__}", severity="high"))
            stop = True
            continue
        hits.extend(res_hits)
        stop = stop or res_stop or res_critical
        critical = critical or res_critical
    return MonitorResult(hits=hits, stop=stop, critical=critical)


def _turn_from(conv: _Conv, index: int, message: str, result: TurnResult) -> Turn:
    return Turn(
        conversation_id=conv.spec.conversation_id,
        index=index,
        message=message,
        response_text=result.response_text,
        tool_calls=result.tool_calls,
        http_status=result.http_status,
        latency_ms=max(0.0, result.latency_ms),
        monitor_hits=[],
        error=str(result.error) if result.error is not None else None,
    )


def _metrics_alert(runtime: CampaignRuntime, cid: str, turn_index: int, hits: list[str]) -> None:
    target = runtime.request.target
    _safe_metrics(
        lambda: get_metrics().alert(
            "Canary: critical monitor hit",
            f"campaign={runtime.campaign_id} conversation={cid} turn={turn_index} "
            f"target={target.target_id} env={target.environment} hits={', '.join(hits)}",
            "ERROR",
        )
    )


async def _notify_on_call(runtime: CampaignRuntime, cid: str, turn_index: int, hits: list[str]) -> None:
    """Call the target's on-call hook, bounded. Never raises, except a genuine
    cancellation of this task (worker shutdown)."""
    deps = runtime.deps
    if deps.on_call is None:
        return
    target = runtime.request.target
    alert = OnCallAlert(
        campaign_id=runtime.campaign_id, conversation_id=cid, target_id=target.target_id,
        environment=target.environment, turn_index=turn_index, hits=list(hits),
    )
    failure: str | None = None
    try:
        async with asyncio.timeout(deps.hook_timeout_s):
            await deps.on_call(alert)
    except asyncio.CancelledError:
        if _genuinely_cancelled():
            raise
        failure = "cancelled"
    except TimeoutError:
        failure = "timed out"
    except Exception as exc:
        failure = type(exc).__name__
    if failure is not None:
        logger.error("on-call notifier failed for campaign %s: %s", runtime.campaign_id, failure)
        _safe_metrics(
            lambda: get_metrics().alert(
                "Canary: on-call notification failed",
                f"campaign={runtime.campaign_id} conversation={cid} turn={turn_index} reason={failure}",
                "ERROR",
            )
        )


def _persist_terminal(runtime: CampaignRuntime, conv: _Conv, status: ConversationStatus) -> None:
    try:
        runtime.deps.repos.conversations.set_status(
            conv.spec.conversation_id, status, target_session_ref=conv.session_ref
        )
        conv.persisted_status = status
    except Exception:
        logger.error("could not persist status %s for %s", status, conv.spec.conversation_id)


async def _send(runtime: CampaignRuntime, conv: _Conv, message: str) -> TurnResult:
    """Send with a RunControl watcher that cancels the adapter mid-send."""
    adapter = conv.adapter
    assert adapter is not None
    deps = runtime.deps

    async def watch() -> None:
        while True:
            await asyncio.sleep(deps.control_poll_s)
            signal = await _control(deps, runtime.campaign_id)
            if signal:
                conv.abort = conv.abort or _SIGNAL_STATUS[signal]
                adapter.cancel()
                return

    watcher = asyncio.create_task(watch())
    try:
        return await adapter.send(message)
    finally:
        watcher.cancel()
        try:
            await watcher
        except asyncio.CancelledError:
            if _genuinely_cancelled():
                raise


@trace_op("engine.turn")
async def _turn_step(runtime: CampaignRuntime, conv: _Conv) -> ConversationStatus | None:
    """Run one turn. Returns a terminal status to stop, or ``None`` to continue."""
    deps = runtime.deps
    policy = runtime.request.policy
    cid = conv.spec.conversation_id
    index = len(conv.turns)
    if index >= policy.max_turns:
        return "completed"

    signal = await _control(deps, runtime.campaign_id)
    if signal:
        return _SIGNAL_STATUS[signal]
    if runtime.stop_requested:
        return "completed"
    if runtime.ledger.exhausted():
        return "stopped_budget"

    state = ConversationState(
        campaign_id=runtime.campaign_id,
        conversation_id=cid,
        technique=conv.spec.technique,
        trial_index=conv.spec.trial_index,
        turns=list(conv.turns),
        monitor_hits=[h for t in conv.turns for h in t.monitor_hits],
        max_turns=policy.max_turns,
        remaining_turns=policy.max_turns - index,
    )
    if conv.planner is None:
        raise RuntimeError("no planner")
    async with asyncio.timeout(deps.planner_timeout_s):  # a hang ends the conversation as error
        planned = await _plan(conv.planner, state)
    if planned is not None:
        await runtime.ledger.charge_llm(planned.llm_tokens, planned.llm_cost_usd)
    # end_conversation means "stop here": the message is not sent.
    if planned is None or planned.end_conversation:
        return "completed"

    # Planning can take a while: re-check right before sending.
    signal = await _control(deps, runtime.campaign_id)
    if signal:
        return _SIGNAL_STATUS[signal]

    conv.abort = None
    result = await _send(runtime, conv, planned.message)
    if result.attempts == 0 and conv.abort is not None:
        return conv.abort  # refused before anything was sent: no turn to record

    draft = _turn_from(conv, index, planned.message, result)
    verdict = await _run_monitors(runtime, conv.context, draft)
    hit_names = list(dict.fromkeys(h.name for h in verdict.hits))
    turn = draft.model_copy(update={"monitor_hits": hit_names})
    if verdict.critical:
        _metrics_alert(runtime, cid, index, hit_names)  # first, whatever happens next

    adapter = conv.adapter
    new_ref = adapter.session_id if adapter is not None else None
    ref_changed = bool(new_ref) and new_ref != conv.session_ref
    if ref_changed:
        conv.session_ref = new_ref
    try:
        deps.repos.conversations.append_turn(turn, deps.canary_values)
    finally:
        if verdict.stop:
            _persist_terminal(runtime, conv, "stopped_monitor")
        if verdict.critical:
            await _notify_on_call(runtime, cid, index, hit_names)
    conv.turns.append(turn)
    if not verdict.stop and ref_changed:
        deps.repos.conversations.set_status(cid, "running", target_session_ref=conv.session_ref)
    runtime.turns_total += 1
    runtime.monitor_hits_total += len(hit_names)

    canaries = _masked_values(runtime)
    await _emit(
        deps,
        "turn",
        TurnPayload(
            campaign_id=runtime.campaign_id,
            conversation_id=cid,
            index=turn.index,
            message_preview=redact(turn.message, canaries).text,
            response_preview=redact(turn.response_text, canaries).text,
            tool_call_names=[c.name for c in turn.tool_calls],
            http_status=turn.http_status,
            latency_ms=turn.latency_ms,
            monitor_hits=hit_names,
            error=redact(turn.error, canaries).text if turn.error else None,
        ),
    )
    for hit in verdict.hits:
        await _emit(
            deps,
            "monitor_hit",
            MonitorHitPayload(
                campaign_id=runtime.campaign_id, conversation_id=cid, turn_index=turn.index,
                hit=hit.name, severity=hit.severity, stops_conversation=verdict.stop,
            ),
        )
    await _emit(deps, "budget_update", runtime.ledger.snapshot())
    _safe_metrics(
        lambda: get_metrics().log(
            runtime.campaign_id,
            {
                "turns_total": float(runtime.turns_total),
                "requests_total": float(runtime.ledger.requests_used),
                "budget_remaining_pct": runtime.ledger.remaining_pct(),
                "monitor_hits": float(runtime.monitor_hits_total),
            },
            step=runtime.turns_total,
        )
    )

    if verdict.stop:
        return "stopped_monitor"
    if conv.abort is not None:
        return conv.abort  # some attempts were sent, then refused

    conv.error_streak = conv.error_streak + 1 if turn.error else 0
    if conv.error_streak >= ERROR_STREAK_LIMIT:
        _safe_metrics(
            lambda: get_metrics().alert(
                "Canary: target error streak",
                f"campaign={runtime.campaign_id} conversation={cid} errors={conv.error_streak}",
                "WARN",
            )
        )
        return "stopped_target_error_streak"
    if len(conv.turns) >= policy.max_turns:
        return "completed"
    return None


async def _recheck_last_turn(runtime: CampaignRuntime, conv: _Conv) -> bool:
    """On resume: re-run the monitors on the last persisted turn. True if the
    conversation must stop (its stop status may have been lost in a crash)."""
    last = conv.turns[-1]
    verdict = await _run_monitors(runtime, conv.context, last)
    if not verdict.stop:
        return False
    names = list(dict.fromkeys(h.name for h in verdict.hits))
    if verdict.critical:
        _metrics_alert(runtime, conv.spec.conversation_id, last.index, names)
    _persist_terminal(runtime, conv, "stopped_monitor")
    if verdict.critical:
        await _notify_on_call(runtime, conv.spec.conversation_id, last.index, names)
    return True


@trace_op("engine.run_conversation")
async def run_conversation(spec: ConversationSpec, runtime: CampaignRuntime) -> ConversationResult:
    """Run (or resume) one conversation to a terminal status."""
    deps = runtime.deps
    repo = deps.repos.conversations
    cid = spec.conversation_id
    existing = repo.get(cid)
    if existing is not None and existing.status in TERMINAL_CONVERSATION_STATUSES:
        # A crash may have hit between the terminal status and the verdict: the
        # evaluator is idempotent, so this costs nothing when a verdict exists.
        await _evaluate(runtime, cid, existing.status, len(existing.turns))
        return ConversationResult(
            conversation_id=cid, technique=spec.technique, trial_index=spec.trial_index,
            status=existing.status, turns=len(existing.turns), skipped=True,
        )

    resumed = existing is not None
    turns: list[Turn] = []
    session_ref: str | None = None
    if existing is None:
        repo.create(
            Conversation(
                conversation_id=cid,
                campaign_id=runtime.campaign_id,
                technique=spec.technique,
                trial_index=spec.trial_index,
            )
        )
        await _emit(
            deps,
            "conversation_started",
            ConversationStartedPayload(
                campaign_id=runtime.campaign_id, conversation_id=cid,
                technique=spec.technique, trial_index=spec.trial_index,
            ),
        )
    else:
        session_ref = existing.target_session_ref
        if existing.turns:
            # The redacted default is truncated preview text; resuming must
            # replay the real transcript. This raw read is audited.
            raw = repo.get(cid, raw=True, actor=RESUME_ACTOR)
            turns = list(raw.turns) if raw is not None else []

    target = runtime.request.target
    conv = _Conv(
        spec=spec,
        planner=None,
        context=MonitorContext(
            campaign_id=runtime.campaign_id,
            conversation_id=cid,
            technique=spec.technique,
            target=target,
            canary_values=tuple(deps.canary_values),
            forbidden_tools=frozenset(deps.forbidden_tools),
            allow_destructive_tools=runtime.request.policy.allow_destructive_tools,
        ),
        turns=turns,
        session_ref=session_ref,
        error_streak=_trailing_errors(turns),
    )

    async def before_attempt() -> None:
        signal = await _control(deps, runtime.campaign_id)
        if signal:
            conv.abort = _SIGNAL_STATUS[signal]
            raise SendAborted(signal)
        if not await runtime.ledger.charge_request():
            conv.abort = "stopped_budget"
            raise SendAborted("budget")

    status: ConversationStatus
    adapter: SessionAdapter | None = None
    fatal: BaseException | None = None  # a campaign-level planner config error
    try:
        conv.planner = deps.planner_factory(spec)
        if turns and await _recheck_last_turn(runtime, conv):
            status = "stopped_monitor"
        else:
            adapter = deps.adapter_factory(target, runtime.campaign_id, runtime.limiter, before_attempt)
            conv.adapter = adapter
            history = _history_from(turns) if target.session_mode == "stateless_history" else []
            if history or session_ref:
                adapter.restore(history, session_ref if target.session_mode == "server_session" else None)
            while True:
                outcome = await _turn_step(runtime, conv)
                if outcome is not None:
                    status = outcome
                    break
    except (Exception, asyncio.CancelledError) as exc:
        if isinstance(exc, asyncio.CancelledError) and _genuinely_cancelled():
            raise  # worker shutdown: stays "running" unless a terminal status was persisted
        # Any other failure, including a CancelledError raised by the planner,
        # planner factory, adapter or a hook on its own, ends the conversation.
        from cyberredteam.planners.errors import (
            PlannerGuardrailStop,  # lazy: avoids an import cycle
        )

        if isinstance(exc, PlannerGuardrailStop):
            logger.error("conversation %s stopped by a planner guard rail (%s)", cid, exc.reason)
            status = conv.persisted_status or "stopped_planner_guardrail"
            # The refused planner call still cost tokens/USD: charge it (an invalid
            # amount makes the ledger count the budget as exhausted).
            await runtime.ledger.charge_llm(exc.llm_tokens, exc.llm_cost_usd)
        else:
            logger.error("conversation %s failed: %s", cid, type(exc).__name__)
            status = conv.persisted_status or "error"
            if getattr(exc, "campaign_fatal", False) is True:
                fatal = exc
    finally:
        if adapter is not None:
            try:
                await adapter.aclose()
            except Exception:
                logger.warning("adapter close failed for %s", cid)

    if conv.persisted_status != status:
        _persist_terminal(runtime, conv, status)
    await _emit(
        deps,
        "conversation_finished",
        ConversationFinishedPayload(
            campaign_id=runtime.campaign_id, conversation_id=cid, status=status, turns=len(turns),
        ),
    )
    if fatal is not None:
        raise fatal  # fails the campaign once (run_campaign / run_campaign_graph)
    await _evaluate(runtime, cid, status, len(turns))
    return ConversationResult(
        conversation_id=cid, technique=spec.technique, trial_index=spec.trial_index,
        status=status, turns=len(turns), resumed=resumed,
    )


# ── Campaign ─────────────────────────────────────────────────────────────────


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _is_finite(value: object, *, positive: bool) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return bool(math.isfinite(value) and (value > 0 if positive else value >= 0))
    except (OverflowError, TypeError, ValueError):
        return False


def policy_sanity_violations(policy: CampaignPolicy) -> list[str]:
    """Engine invariants for every environment, even on an unvalidated
    (``model_construct``) policy: whole positive counts, a finite positive
    rate, a finite non-negative USD cap, a real boolean, unique techniques."""
    problems: list[str] = []
    for name in ("trials_per_technique", "max_turns", "max_parallel_conversations", "max_total_requests"):
        if not _is_count(getattr(policy, name, None)):
            problems.append(f"{name} must be a whole number >= 1")
    if not _is_finite(getattr(policy, "rate_limit_rps", None), positive=True):
        problems.append("rate_limit_rps must be finite and > 0")
    if not _is_finite(getattr(policy, "max_llm_cost_usd", None), positive=False):
        problems.append("max_llm_cost_usd must be finite and >= 0")
    if not isinstance(getattr(policy, "allow_destructive_tools", None), bool):
        problems.append("allow_destructive_tools must be a boolean")
    techniques = getattr(policy, "techniques", None)
    if (
        not isinstance(techniques, (list, tuple))
        or not techniques
        or not all(type(t) is str and t.strip() for t in techniques)
        or len({normalize_technique(t) for t in techniques}) != len(techniques)
    ):
        problems.append("techniques must be a non-empty list of unique names")
    return problems


def check_campaign_allowed(request: CampaignRequest) -> None:
    """Defence in depth, before anything is written. Fails closed even when
    ``CampaignRequest`` validation was bypassed (``model_construct``):

    * the target must be verified, with ``verified is True`` exactly;
    * any environment other than exactly ``"staging"`` gets the production
      rules (``CampaignPolicy.production_violations``);
    * :func:`policy_sanity_violations` must be empty.
    """
    target = getattr(request, "target", None)
    policy = getattr(request, "policy", None)
    if getattr(target, "verified", None) is not True:
        raise CampaignRefused("target is not verified")
    if not isinstance(policy, CampaignPolicy):
        raise CampaignRefused("campaign policy rejected: not a CampaignPolicy")
    problems = policy_sanity_violations(policy)
    env = getattr(target, "environment", None)
    if not (type(env) is str and env == "staging"):
        problems += policy.production_violations()
    if problems:
        raise CampaignRefused("campaign policy rejected: " + "; ".join(problems))


def normalize_request(request: Any) -> CampaignRequest:
    """Rebuild ``request`` from plain JSON data and validate it again, then run
    :func:`check_campaign_allowed` on both the original and the copy.

    This strips str/int/float subclasses, ``__eq__`` tricks, Decimals, NaN/inf
    and huge integers, missing attributes and ``None``/dict policies left by
    ``model_construct``: they either become plain validated values or fail.
    Any failure is a :class:`CampaignRefused` with a generic reason. Nothing
    is written before this returns; the engine uses only the returned copy.
    """
    try:
        # First layer on the original object: verified must already be exactly True
        # (a forged "true" string must not become True through re-validation).
        if type(request) is not CampaignRequest:  # no subclasses (they can override validation)
            raise TypeError("not a CampaignRequest")
        if getattr(getattr(request, "target", None), "verified", None) is not True:
            raise CampaignRefused("target is not verified")
        # JSON mode turns URLs, subclasses etc. into plain data; secrets serialise
        # masked there, so the auth block is re-added with its secrets revealed.
        raw = request.model_dump(mode="json", warnings=False)
        auth = request.target.auth
        auth_raw = auth.model_dump(mode="json", warnings=False)
        for name, value in auth:
            if isinstance(value, SecretStr):
                auth_raw[name] = value.get_secret_value()
        raw["target"]["auth"] = auth_raw
        text = json.dumps(raw, allow_nan=False)
        # Strict: no lax coercion of forged values ("no" -> False, True -> 1).
        normalized = CampaignRequest.model_validate_json(text, strict=True)
        # Second layer, on the original and on the plain copy.
        check_campaign_allowed(request)
        check_campaign_allowed(normalized)
        return normalized
    except CampaignRefused:
        raise
    except Exception as exc:
        raise CampaignRefused(f"campaign request rejected ({type(exc).__name__})") from None


async def begin_campaign(request: CampaignRequest, campaign_id: str, deps: EngineDeps) -> CampaignRuntime:
    """Normalise and check the request (refusing unsafe launches), create
    (idempotently) the campaign row, mark it running, emit the start. The
    returned runtime holds the normalised request; callers must use
    ``runtime.request`` from here on."""
    request = normalize_request(request)
    # Build the runtime (ledger totals, limiter) first: if that fails, no
    # campaign row has been left "running".
    runtime = CampaignRuntime.create(request, campaign_id, deps)
    campaigns = deps.repos.campaigns
    if campaigns.get(campaign_id) is None:
        campaigns.create(campaign_id, request.target.target_id, request.policy)
    campaigns.set_status(campaign_id, "running")
    policy = request.policy
    total = len(policy.techniques) * policy.trials_per_technique
    _safe_metrics(
        lambda: get_metrics().campaign_started(
            campaign_id,
            {
                "policy": policy.model_dump(mode="json"),
                "target_id": request.target.target_id,
                "environment": request.target.environment,
                "session_mode": request.target.session_mode,
            },
        )
    )
    await _emit(
        deps,
        "campaign_started",
        CampaignStartedPayload(
            campaign_id=campaign_id,
            target_id=request.target.target_id,
            environment=request.target.environment,
            techniques=list(policy.techniques),
            trials_per_technique=policy.trials_per_technique,
            total_conversations=total,
        ),
    )
    return runtime


def _aggregate(runtime: CampaignRuntime) -> CampaignAggregate:
    """Technique results and verdict counts from the evaluation wiring; empty
    (never a guess) when none is configured or it fails."""
    fn = runtime.deps.aggregate_results
    if fn is None:
        return CampaignAggregate()
    try:
        return fn(runtime.campaign_id)
    except Exception as exc:
        logger.error("campaign aggregation failed for %s: %s", runtime.campaign_id, type(exc).__name__)
        return CampaignAggregate()


async def finish_campaign(
    runtime: CampaignRuntime, results: list[ConversationResult], started: float
) -> CampaignOutcome:
    deps = runtime.deps
    statuses = Counter(r.status for r in results)
    status: CampaignOutcomeStatus
    if statuses["stopped_killed"]:
        status = "killed"
    elif statuses["cancelled"]:
        status = "cancelled"
    else:
        status = "completed"
    deps.repos.campaigns.set_status(runtime.campaign_id, "completed" if status == "completed" else "cancelled")
    duration = max(0.0, deps.clock() - started)
    aggregate = _aggregate(runtime)
    confirmed = sum(r.confirmed for r in aggregate.technique_results)
    outcome = CampaignOutcome(
        campaign_id=runtime.campaign_id,
        status=status,
        conversations=results,
        requests_used=runtime.ledger.requests_used,
        llm_cost_usd=runtime.ledger.llm_cost_usd,
        duration_seconds=duration,
    )
    if status == "completed":
        await _emit(
            deps,
            "campaign_complete",
            CampaignCompletePayload(
                campaign_id=runtime.campaign_id, conversations=len(results), confirmed=confirmed,
                technique_results=aggregate.technique_results, duration_seconds=duration,
            ),
        )
    else:
        await _emit(
            deps,
            "campaign_cancelled",
            CampaignCancelledPayload(
                campaign_id=runtime.campaign_id,
                reason="kill_switch" if status == "killed" else "user",
            ),
        )
        if status == "killed":
            _safe_metrics(
                lambda: get_metrics().alert(
                    "Canary: kill switch", f"campaign={runtime.campaign_id} halted", "WARN"
                )
            )
    if runtime.ledger.write_failed:
        _safe_metrics(
            lambda: get_metrics().alert(
                "Canary: budget ledger write failed",
                f"campaign={runtime.campaign_id} stopped fail-closed",
                "ERROR",
            )
        )
    _safe_metrics(
        lambda: get_metrics().campaign_finished(
            runtime.campaign_id,
            {
                "status": status,
                "conversations": len(results),
                "skipped": outcome.skipped,
                "statuses": dict(statuses),
                "turns_total": runtime.turns_total,
                "requests_total": runtime.ledger.requests_used,
                "llm_cost_usd": runtime.ledger.llm_cost_usd,
                "monitor_hits": runtime.monitor_hits_total,
                "duration_seconds": duration,
                # Documented campaign_finished keys (observability/wandb_metrics.py).
                "technique_results": [
                    {
                        "technique": r.technique, "success_rate": r.success_rate,
                        "ci_low": r.ci95_low, "ci_high": r.ci95_high,
                        "trials": r.trials, "successes": r.confirmed,
                    }
                    for r in aggregate.technique_results
                ],
                "verdict_counts": dict(aggregate.verdict_counts),
                "headline": {"confirmed": confirmed, "conversations": len(results)},
            },
        )
    )
    return outcome


async def fail_campaign(runtime: CampaignRuntime, exc: BaseException) -> None:
    try:
        runtime.deps.repos.campaigns.set_status(runtime.campaign_id, "failed")
    except Exception:
        logger.error("could not mark campaign %s failed", runtime.campaign_id)
    await _emit(
        runtime.deps,
        "campaign_failed",
        CampaignFailedPayload(campaign_id=runtime.campaign_id, message=f"engine error: {type(exc).__name__}"),
    )
    _safe_metrics(lambda: get_metrics().campaign_finished(runtime.campaign_id, {"status": "failed"}))


@trace_op("engine.run_campaign")
async def run_campaign(request: CampaignRequest, campaign_id: str, deps: EngineDeps) -> CampaignOutcome:
    """Run every technique x trial conversation, at most
    ``max_parallel_conversations`` at a time. Idempotent and resumable per
    ``campaign_id``. Raises :class:`CampaignRefused` (before writing anything)
    for an unverified target or a production-policy violation. A task
    cancellation propagates and leaves unfinished conversations ``running``."""
    started = deps.clock()
    runtime = await begin_campaign(request, campaign_id, deps)
    request = runtime.request  # the normalised copy only
    specs = plan_conversations(request, campaign_id)
    sem = asyncio.Semaphore(request.policy.max_parallel_conversations)

    async def guarded(spec: ConversationSpec) -> ConversationResult | None:
        async with sem:
            if runtime.stop_requested:  # stop_on_first_confirmed: not started
                return None
            return await run_conversation(spec, runtime)

    try:
        async with asyncio.TaskGroup() as tg:
            tasks = [tg.create_task(guarded(s)) for s in specs]
    except asyncio.CancelledError as exc:
        if _genuinely_cancelled():
            raise
        await fail_campaign(runtime, exc)
        raise RuntimeError("campaign run cancelled without a cancel request") from None
    except BaseExceptionGroup as group:
        await fail_campaign(runtime, group.exceptions[0])
        raise
    if any(t.cancelled() for t in tasks):
        # A child raised CancelledError on its own (a genuine cancel of this task
        # would have raised out of the TaskGroup above). TaskGroup ignores it, and
        # t.result() below would raise outside every handler, leaving the campaign
        # "running": fail it explicitly.
        await fail_campaign(runtime, asyncio.CancelledError())
        raise RuntimeError("campaign run cancelled without a cancel request")
    results = [r for r in (t.result() for t in tasks) if r is not None]
    return await finish_campaign(runtime, results, started)


__all__ = [
    "AdapterFactory",
    "BeforeAttempt",
    "CampaignOutcome",
    "CampaignRefused",
    "CampaignRuntime",
    "ConversationResult",
    "ERROR_STREAK_LIMIT",
    "EngineDeps",
    "EngineRepos",
    "LimiterFactory",
    "begin_campaign",
    "check_campaign_allowed",
    "normalize_request",
    "normalize_technique",
    "policy_sanity_violations",
    "default_adapter_factory",
    "finish_campaign",
    "fail_campaign",
    "plan_conversations",
    "run_campaign",
    "run_conversation",
]
