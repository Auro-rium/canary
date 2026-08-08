"""Durable-release execution primitives.

This module deliberately has no FastAPI, ORM, Redis, or RQ dependency.  The
API can persist a :class:`ReleaseExecution` and enqueue ``job_id`` after its
transaction commits; an RQ worker can later call :meth:`ReleaseExecutor.run`
with a project-specific work function.  Keeping the lifecycle here makes the
transition rules testable before the transport/storage adapters are wired in.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from threading import RLock
from typing import Any, Protocol
from uuid import uuid4


class ReleaseExecutionStatus(StrEnum):
    """Terminal and non-terminal states for a release evaluation."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {
            ReleaseExecutionStatus.COMPLETED,
            ReleaseExecutionStatus.FAILED,
            ReleaseExecutionStatus.CANCELLED,
        }


class ReleaseExecutionEventKind(StrEnum):
    """A compact, persisted audit vocabulary for release progress."""

    QUEUED = "queued"
    STARTED = "started"
    ATTEMPT_STARTED = "attempt_started"
    RETRY_SCHEDULED = "retry_scheduled"
    CANCELLATION_REQUESTED = "cancellation_requested"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def deterministic_job_id(release_id: str) -> str:
    """Return a stable queue key suitable for RQ's ``job_id`` argument.

    The input is prefixed and SHA-256 encoded so arbitrary release identifiers
    cannot introduce queue-key separators or implementation-specific limits.
    """

    if not release_id or not release_id.strip():
        raise ValueError("release_id must not be blank")
    digest = sha256(release_id.encode("utf-8")).hexdigest()
    return f"canary-release-{digest}"


@dataclass(frozen=True, slots=True)
class ReleaseStageEvent:
    """JSON-persistable event emitted during an execution lifecycle."""

    event_id: str
    release_id: str
    sequence: int
    kind: ReleaseExecutionEventKind
    status: ReleaseExecutionStatus
    occurred_at: datetime
    attempt: int = 0
    stage: str | None = None
    message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["kind"] = self.kind.value
        record["status"] = self.status.value
        record["occurred_at"] = self.occurred_at.isoformat()
        return record

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "ReleaseStageEvent":
        return cls(
            event_id=str(record["event_id"]),
            release_id=str(record["release_id"]),
            sequence=int(record["sequence"]),
            kind=ReleaseExecutionEventKind(str(record["kind"])),
            status=ReleaseExecutionStatus(str(record["status"])),
            occurred_at=datetime.fromisoformat(str(record["occurred_at"])),
            attempt=int(record.get("attempt", 0)),
            stage=record.get("stage"),
            message=record.get("message"),
            details=dict(record.get("details") or {}),
        )


@dataclass(slots=True)
class ReleaseExecution:
    """Persistable lifecycle state, intentionally independent of ORM models."""

    release_id: str
    job_id: str
    status: ReleaseExecutionStatus = ReleaseExecutionStatus.QUEUED
    attempt: int = 0
    max_attempts: int = 3
    cancellation_requested: bool = False
    failure_code: str | None = None
    failure_message: str | None = None
    created_at: datetime = field(default_factory=_utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def to_record(self) -> dict[str, Any]:
        return {
            "release_id": self.release_id,
            "job_id": self.job_id,
            "status": self.status.value,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "cancellation_requested": self.cancellation_requested,
            "failure_code": self.failure_code,
            "failure_message": self.failure_message,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "ReleaseExecution":
        def parse_optional(name: str) -> datetime | None:
            value = record.get(name)
            return datetime.fromisoformat(str(value)) if value else None

        return cls(
            release_id=str(record["release_id"]),
            job_id=str(record["job_id"]),
            status=ReleaseExecutionStatus(str(record["status"])),
            attempt=int(record.get("attempt", 0)),
            max_attempts=int(record.get("max_attempts", 3)),
            cancellation_requested=bool(record.get("cancellation_requested", False)),
            failure_code=record.get("failure_code"),
            failure_message=record.get("failure_message"),
            created_at=datetime.fromisoformat(str(record["created_at"])),
            started_at=parse_optional("started_at"),
            completed_at=parse_optional("completed_at"),
        )


class ReleaseExecutionStore(Protocol):
    """Persistence port to be implemented by SQLAlchemy/Postgres later."""

    def get(self, release_id: str) -> ReleaseExecution | None: ...

    def save(self, execution: ReleaseExecution) -> None: ...

    def append_event(self, event: ReleaseStageEvent) -> None: ...

    def events_for(self, release_id: str) -> list[ReleaseStageEvent]: ...


class RetryableReleaseError(RuntimeError):
    """A work function may raise this to use the bounded retry budget."""


class ReleaseCancelled(RuntimeError):
    """Raised by cooperative work after a cancellation request."""


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Passed to work; polling ``cancelled`` is safe between slow stages."""

    release_id: str
    job_id: str
    attempt: int
    _cancelled: Callable[[], bool] = field(repr=False, compare=False)

    @property
    def cancelled(self) -> bool:
        return self._cancelled()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise ReleaseCancelled("release cancellation was requested")


ReleaseWork = Callable[[ExecutionContext], None]


class InMemoryReleaseExecutionStore:
    """Thread-safe reference adapter used by tests and local development.

    It intentionally returns copies from ``get`` so callers cannot mutate
    persisted state without ``save``.  Production adapters should offer the
    same logical atomicity per release.
    """

    def __init__(self) -> None:
        self._executions: dict[str, dict[str, Any]] = {}
        self._events: dict[str, list[dict[str, Any]]] = {}
        self._lock = RLock()

    def get(self, release_id: str) -> ReleaseExecution | None:
        with self._lock:
            record = self._executions.get(release_id)
            return ReleaseExecution.from_record(dict(record)) if record else None

    def save(self, execution: ReleaseExecution) -> None:
        with self._lock:
            self._executions[execution.release_id] = execution.to_record()

    def append_event(self, event: ReleaseStageEvent) -> None:
        with self._lock:
            self._events.setdefault(event.release_id, []).append(event.to_record())

    def events_for(self, release_id: str) -> list[ReleaseStageEvent]:
        with self._lock:
            return [ReleaseStageEvent.from_record(dict(item)) for item in self._events.get(release_id, [])]


class ReleaseExecutor:
    """Idempotent lifecycle coordinator suitable for an in-process or RQ worker."""

    def __init__(self, store: ReleaseExecutionStore, *, now: Callable[[], datetime] = _utc_now) -> None:
        self._store = store
        self._now = now

    def enqueue(self, release_id: str, *, max_attempts: int = 3) -> ReleaseExecution:
        """Create the queued state once; repeated calls return the same job."""

        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        existing = self._store.get(release_id)
        if existing:
            return existing
        execution = ReleaseExecution(
            release_id=release_id,
            job_id=deterministic_job_id(release_id),
            max_attempts=max_attempts,
        )
        self._store.save(execution)
        self._event(execution, ReleaseExecutionEventKind.QUEUED, message="release evaluation queued")
        return execution

    def request_cancellation(self, release_id: str) -> ReleaseExecution:
        execution = self._required(release_id)
        if execution.status.terminal:
            return execution
        execution.cancellation_requested = True
        self._store.save(execution)
        self._event(execution, ReleaseExecutionEventKind.CANCELLATION_REQUESTED, message="cancellation requested")
        if execution.status is ReleaseExecutionStatus.QUEUED:
            self._cancel(execution)
        return execution

    def run(self, release_id: str, work: ReleaseWork) -> ReleaseExecution:
        """Run one release to a terminal state, safely tolerating duplicate jobs."""

        execution = self._required(release_id)
        if execution.status.terminal:
            return execution
        # Queue delivery is at-least-once.  A duplicate worker must not run a
        # second attack campaign while the original attempt is still active.
        if execution.status is ReleaseExecutionStatus.RUNNING:
            return execution
        if execution.cancellation_requested:
            return self._cancel(execution)
        execution.status = ReleaseExecutionStatus.RUNNING
        execution.started_at = execution.started_at or self._now()
        self._store.save(execution)
        self._event(execution, ReleaseExecutionEventKind.STARTED, message="release evaluation started")

        while execution.attempt < execution.max_attempts:
            if self._required(release_id).cancellation_requested:
                return self._cancel(execution)
            execution.attempt += 1
            self._store.save(execution)
            self._event(execution, ReleaseExecutionEventKind.ATTEMPT_STARTED, stage="release", message="attempt started")
            context = ExecutionContext(
                release_id=execution.release_id,
                job_id=execution.job_id,
                attempt=execution.attempt,
                _cancelled=lambda: bool(self._required(release_id).cancellation_requested),
            )
            try:
                work(context)
                context.raise_if_cancelled()
            except ReleaseCancelled:
                return self._cancel(execution)
            except RetryableReleaseError as exc:
                if execution.attempt < execution.max_attempts:
                    self._event(
                        execution,
                        ReleaseExecutionEventKind.RETRY_SCHEDULED,
                        stage="release",
                        message=self._safe_message(exc),
                    )
                    continue
                return self._fail(execution, "retry_exhausted", self._safe_message(exc))
            except Exception as exc:  # Persist unexpected worker failures too.
                return self._fail(execution, "execution_failed", self._safe_message(exc))
            else:
                execution.status = ReleaseExecutionStatus.COMPLETED
                execution.completed_at = self._now()
                self._store.save(execution)
                self._event(execution, ReleaseExecutionEventKind.COMPLETED, message="release evaluation completed")
                return execution
        return self._fail(execution, "retry_exhausted", "release retries exhausted")

    def _required(self, release_id: str) -> ReleaseExecution:
        execution = self._store.get(release_id)
        if not execution:
            raise KeyError(f"unknown release execution: {release_id}")
        return execution

    def _cancel(self, execution: ReleaseExecution) -> ReleaseExecution:
        execution.cancellation_requested = True
        execution.status = ReleaseExecutionStatus.CANCELLED
        execution.completed_at = self._now()
        self._store.save(execution)
        self._event(execution, ReleaseExecutionEventKind.CANCELLED, message="release evaluation cancelled")
        return execution

    def _fail(self, execution: ReleaseExecution, code: str, message: str) -> ReleaseExecution:
        execution.status = ReleaseExecutionStatus.FAILED
        execution.failure_code = code
        execution.failure_message = message
        execution.completed_at = self._now()
        self._store.save(execution)
        self._event(execution, ReleaseExecutionEventKind.FAILED, message=message, details={"failure_code": code})
        return execution

    def _event(
        self,
        execution: ReleaseExecution,
        kind: ReleaseExecutionEventKind,
        *,
        stage: str | None = None,
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        sequence = len(self._store.events_for(execution.release_id)) + 1
        self._store.append_event(
            ReleaseStageEvent(
                event_id=str(uuid4()),
                release_id=execution.release_id,
                sequence=sequence,
                kind=kind,
                status=execution.status,
                occurred_at=self._now(),
                attempt=execution.attempt,
                stage=stage,
                message=message,
                details=details or {},
            )
        )

    @staticmethod
    def _safe_message(exc: Exception) -> str:
        # Keep database/SSE fields bounded; integrations should provide a
        # sanitized message rather than allow accidental credential dumps.
        return str(exc).replace("\n", " ")[:500] or exc.__class__.__name__
