"""Weave tracing for Canary (WP11). Every function here is best-effort.

``init_tracing`` calls ``weave.init`` and installs :func:`build_tracer` via
``hooks.set_tracer``. Because ``@trace_op`` is resolved at decoration (import)
time, and the engine modules are usually imported before startup runs,
``init_tracing`` also instruments the known ops in place
(:func:`instrument_known_ops`). The tracer returns a *plain function* wrapper
around the ``weave.op`` (never an ``Op`` object), so it is safe on pydantic
model methods such as ``ChatBackboard._generate``.

Exports go through ``postprocess_inputs`` / ``postprocess_output`` hooks that
apply :mod:`cyberredteam.observability.redact`: auth headers, secrets and
``SecretStr`` are dropped; text becomes a redacted preview + hash unless raw
evidence export is allowed (flag on AND ``environment == "staging"``).
"""

from __future__ import annotations

import contextlib
import functools
import importlib
import inspect
import logging
from collections.abc import Callable, Iterator
from typing import Any

from cyberredteam.observability import hooks
from cyberredteam.observability.redact import (
    current_environment,
    reset_environment,
    safe_exception_message,
    sanitize,
    sanitize_inputs,
    sanitize_output,
    set_environment,
)

logger = logging.getLogger(__name__)

_MARK = "__canary_traced__"
_initialized = False
_client_hooks = False  # True once weave.init installed client-level sanitizers
_patched: list[tuple[Any, str, Any]] = []

# (module, class or None, attribute, op name)
KNOWN_OPS: tuple[tuple[str, str, str, str], ...] = (
    ("cyberredteam.llm.backboard", "ChatBackboard", "_generate", "backboard.generate"),
    ("cyberredteam.llm.backboard", "ChatBackboard", "_post_message", "backboard.request"),
    ("cyberredteam.transport.session_adapter", "SessionAdapter", "send", "target.send"),
)


def _weave() -> Any | None:
    try:
        import weave

        return weave
    except Exception:
        return None


class _TracedError(Exception):
    """Redacted stand-in raised inside the weave.op so the export is safe."""

    original: BaseException


_proxy_types: dict[str, type[_TracedError]] = {}


def _proxy(exc: BaseException) -> _TracedError:
    name = type(exc).__name__
    cls = _proxy_types.get(name)
    if cls is None:
        cls = _proxy_types[name] = type(name, (_TracedError,), {})
    err = cls(safe_exception_message(exc))
    err.original = exc
    return err


def _client_sanitizes_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    return inputs if _client_hooks else sanitize_inputs(inputs)


def _client_sanitizes_output(output: Any) -> Any:
    return output if _client_hooks else sanitize_output(output)


def build_tracer() -> Callable[[str], Callable[[Any], Any]]:
    """Return a ``trace_op``-compatible tracer backed by ``weave.op``.

    The function handed to ``weave.op`` converts any exception into a redacted
    proxy (weave stores the message and traceback of what it sees); the outer
    wrapper unwraps it again, so callers still receive the original exception.
    """

    def tracer(name: str) -> Callable[[Any], Any]:
        def deco(fn: Any) -> Any:
            if getattr(fn, _MARK, False):
                return fn
            weave = _weave()
            if weave is None:
                return fn

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def inner(*args: Any, **kwargs: Any) -> Any:
                    try:
                        return await fn(*args, **kwargs)
                    except Exception as exc:
                        raise _proxy(exc) from None
            else:

                @functools.wraps(fn)
                def inner(*args: Any, **kwargs: Any) -> Any:
                    try:
                        return fn(*args, **kwargs)
                    except Exception as exc:
                        raise _proxy(exc) from None

            try:
                op = weave.op(
                    name=name,
                    postprocess_inputs=_client_sanitizes_inputs,
                    postprocess_output=_client_sanitizes_output,
                    enable_code_capture=False,
                )(inner)
            except Exception as exc:  # never break import / decoration
                logger.warning("weave.op failed for %s: %s", name, type(exc).__name__)
                return fn

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def awrapper(*args: Any, **kwargs: Any) -> Any:
                    try:
                        return await op(*args, **kwargs)
                    except _TracedError as p:
                        raise p.original from p.original.__cause__

                wrapper: Any = awrapper
            else:

                @functools.wraps(fn)
                def swrapper(*args: Any, **kwargs: Any) -> Any:
                    try:
                        return op(*args, **kwargs)
                    except _TracedError as p:
                        raise p.original from p.original.__cause__

                wrapper = swrapper
            setattr(wrapper, _MARK, True)
            setattr(wrapper, "__canary_orig__", fn)
            return wrapper

        return deco

    return tracer


def instrument_known_ops() -> list[str]:
    """Wrap already-imported ops that were decorated before the tracer existed."""
    done: list[str] = []
    tracer = build_tracer()
    for module_name, cls_name, attr, op_name in KNOWN_OPS:
        try:
            module = importlib.import_module(module_name)
            owner = getattr(module, cls_name)
            fn = owner.__dict__.get(attr)
            if fn is None or getattr(fn, _MARK, False):
                continue
            wrapped = tracer(op_name)(fn)
            if wrapped is not fn:
                setattr(owner, attr, wrapped)
                _patched.append((owner, attr, fn))
                done.append(op_name)
        except Exception as exc:
            logger.warning("could not instrument %s.%s: %s", cls_name, attr, type(exc).__name__)
    return done


def init_tracing(entity: str | None, project: str) -> bool:
    """``weave.init`` + install the tracer. False (no-op) when unavailable.

    May block on the network: callers on a request/startup path must run it in
    a background thread (``setup.init_observability`` does).
    Integrations are NOT auto-patched (LangChain/HF would export raw prompts
    and node state), and client-level hooks sanitize every op's I/O.
    """
    global _initialized, _client_hooks
    if _initialized:
        return True
    weave = _weave()
    if weave is None:
        return False
    try:
        weave.init(
            f"{entity}/{project}" if entity else project,
            settings={"implicitly_patch_integrations": False, "print_call_link": False},
            postprocess_inputs=sanitize_inputs,
            postprocess_output=sanitize_output,
        )
    except Exception as exc:  # W&B down or misconfigured: campaigns still run
        logger.warning("weave.init failed, tracing disabled: %s", type(exc).__name__)
        return False
    _client_hooks = True
    hooks.set_tracer(build_tracer())
    instrument_known_ops()
    _initialized = True
    return True


def reset_tracing() -> None:
    """Undo init_tracing: identity tracer, patched methods restored (tests)."""
    global _initialized, _client_hooks
    for owner, attr, fn in reversed(_patched):
        try:
            setattr(owner, attr, fn)
        except Exception:
            pass
    _patched.clear()
    _initialized = False
    _client_hooks = False
    hooks.set_tracer(hooks._identity_tracer)


# ── Attributes ──────────────────────────────────────────────────────────────

ATTRIBUTE_KEYS = (
    "campaign_id", "conversation_id", "turn_index", "target_id", "technique", "environment",
    "role", "provider", "model_name", "tokens_in", "tokens_out", "latency_ms",
    "est_cost_usd", "http_status", "verdict",
)


@contextlib.contextmanager
def trace_attributes(**attrs: Any) -> Iterator[None]:
    """Attach plan attributes to every Weave call made inside the block.

    ``environment`` also drives the raw-evidence gate (default: production).
    Values are sanitized; ``None`` values are dropped. No-op without weave.
    """
    clean = {k: sanitize(v) for k, v in attrs.items() if v is not None}
    # keep short identifiers/numbers readable: sanitize() previews strings, so
    # pass plain identifiers through when they are not free text.
    for k in ("campaign_id", "conversation_id", "target_id", "technique", "environment",
              "role", "provider", "model_name", "verdict"):
        if attrs.get(k) is not None:
            clean[k] = str(attrs[k])[:120]
    token = set_environment(str(attrs["environment"])) if attrs.get("environment") else None
    try:
        weave = _weave()
        cm: Any = contextlib.nullcontext()
        if weave is not None and _initialized:
            try:
                cm = weave.attributes(clean)
            except Exception:
                cm = contextlib.nullcontext()
        with cm:
            yield
    finally:
        if token is not None:
            with contextlib.suppress(Exception):
                reset_environment(token)


# ── Feedback ────────────────────────────────────────────────────────────────


def _current_call() -> Any | None:
    weave = _weave()
    if weave is None or not _initialized:
        return None
    try:
        return weave.get_current_call()
    except Exception:
        return None


def add_feedback(call: Any | None, feedback_type: str, payload: dict[str, Any]) -> bool:
    """Attach feedback to ``call`` (default: the current Weave call). Never raises."""
    try:
        call = call if call is not None else _current_call()
        if call is None:
            return False
        call.feedback.add(feedback_type, sanitize(payload, raw=False))
        return True
    except Exception as exc:
        logger.warning("weave feedback failed: %s", type(exc).__name__)
        return False


def log_judge_vote(
    call: Any | None, *, judge: str, verdict: str, confidence: float | None = None,
    rationale: str | None = None,
) -> bool:
    """Judge vote as feedback on the turn / conversation call (WP5 calls this)."""
    payload: dict[str, Any] = {"judge": judge, "verdict": verdict}
    if confidence is not None:
        payload["confidence"] = confidence
    if rationale:
        payload["rationale"] = rationale
    return add_feedback(call, "canary.judge_vote", payload)


def log_human_triage(
    call: Any | None, *, finding_id: str, decision: str, reviewer: str,
    judge_verdict: str | None = None,
) -> bool:
    """Human triage decision as feedback, for judge-vs-human agreement (WP8 calls this)."""
    payload = {"finding_id": finding_id, "decision": decision, "reviewer": reviewer}
    if judge_verdict:
        payload["judge_verdict"] = judge_verdict
    return add_feedback(call, "canary.human_triage", payload)


__all__ = [
    "ATTRIBUTE_KEYS", "add_feedback", "build_tracer", "current_environment", "init_tracing",
    "instrument_known_ops", "log_human_triage", "log_judge_vote", "trace_attributes",
]
