from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from canary.release_execution import (  # noqa: E402
    InMemoryReleaseExecutionStore,
    ReleaseCancelled,
    ReleaseExecutionStatus,
    ReleaseExecutor,
    ReleaseStageEvent,
    RetryableReleaseError,
    deterministic_job_id,
)


def test_job_id_is_deterministic_and_nonblank_release_ids_are_required() -> None:
    assert deterministic_job_id("release-123") == deterministic_job_id("release-123")
    assert deterministic_job_id("release-123") != deterministic_job_id("release-124")
    with pytest.raises(ValueError):
        deterministic_job_id("  ")


def test_enqueue_is_idempotent_and_events_are_persistable() -> None:
    store = InMemoryReleaseExecutionStore()
    executor = ReleaseExecutor(store)

    first = executor.enqueue("r-1")
    second = executor.enqueue("r-1", max_attempts=9)

    assert first.job_id == second.job_id
    assert second.max_attempts == 3
    event = store.events_for("r-1")[0]
    assert ReleaseStageEvent.from_record(event.to_record()) == event


def test_completed_run_is_idempotent() -> None:
    store = InMemoryReleaseExecutionStore()
    executor = ReleaseExecutor(store)
    executor.enqueue("r-complete")
    calls: list[int] = []

    def work(context: object) -> None:
        calls.append(1)

    completed = executor.run("r-complete", work)
    replay = executor.run("r-complete", work)

    assert completed.status is ReleaseExecutionStatus.COMPLETED
    assert replay.status is ReleaseExecutionStatus.COMPLETED
    assert calls == [1]


def test_retry_is_bounded_and_persists_failure() -> None:
    store = InMemoryReleaseExecutionStore()
    executor = ReleaseExecutor(store)
    executor.enqueue("r-retry", max_attempts=2)
    attempts: list[int] = []

    def work(context: object) -> None:
        attempts.append(1)
        raise RetryableReleaseError("transient upstream error")

    result = executor.run("r-retry", work)

    assert result.status is ReleaseExecutionStatus.FAILED
    assert result.failure_code == "retry_exhausted"
    assert result.attempt == 2
    assert attempts == [1, 1]
    assert [event.kind.value for event in store.events_for("r-retry")] == [
        "queued", "started", "attempt_started", "retry_scheduled", "attempt_started", "failed"
    ]


def test_queued_cancellation_never_runs_work() -> None:
    store = InMemoryReleaseExecutionStore()
    executor = ReleaseExecutor(store)
    executor.enqueue("r-queued")
    executor.request_cancellation("r-queued")

    result = executor.run("r-queued", lambda _: (_ for _ in ()).throw(AssertionError("must not run")))

    assert result.status is ReleaseExecutionStatus.CANCELLED


def test_running_work_can_cooperatively_cancel() -> None:
    store = InMemoryReleaseExecutionStore()
    executor = ReleaseExecutor(store)
    executor.enqueue("r-running")

    def work(context: object) -> None:
        executor.request_cancellation("r-running")
        assert getattr(context, "cancelled")
        raise ReleaseCancelled()

    result = executor.run("r-running", work)

    assert result.status is ReleaseExecutionStatus.CANCELLED
    kinds = [event.kind.value for event in store.events_for("r-running")]
    assert kinds[-2:] == ["cancellation_requested", "cancelled"]
