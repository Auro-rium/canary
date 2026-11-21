"""WP10 real CampaignLauncher: enqueue via the WP7 queue seam and wait."""

from __future__ import annotations

import threading
import time

import pytest
from storage_v2_support import make_target

from cyberredteam.gate.differential import GatePolicy
from cyberredteam.gate.launcher import LaunchError, QueueCampaignLauncher, suite_techniques
from cyberredteam.gate.runner import GateError, run_gate
from cyberredteam.storage.v2.repositories import CampaignRepo, SqlTargetStore


class FakeQueue:
    """Records the enqueue; a 'worker' thread finishes the campaign shortly after."""

    def __init__(self, factory, final="completed", delay=0.05, never=False):
        self.repo = CampaignRepo(factory)
        self.final, self.delay, self.never = final, delay, never
        self.enqueued: list[str] = []
        self.closed = False

    async def enqueue_campaign(self, campaign_id):
        self.enqueued.append(campaign_id)
        if not self.never:
            threading.Timer(self.delay, lambda: self.repo.set_status(campaign_id, self.final)).start()
        return True

    async def close(self):
        self.closed = True


def _packs(tmp_path):
    for suite, tech in (("alpha", "tech_a"), ("beta", "tech_b")):
        d = tmp_path / suite
        d.mkdir()
        (d / f"{tech}.yaml").write_text(
            f"name: {tech}\nversion: 1\ntechnique: {tech}\nturns:\n  - message: hello\n", encoding="utf-8")
    return tmp_path


def _verified_target(factory, **over):
    store = SqlTargetStore(factory)
    target_id = store.create(make_target(**over))
    store.set_verified(target_id, "header")
    return target_id


def _launcher(factory, queue, tmp_path, **kw):
    kw.setdefault("poll_interval_s", 0.01)
    kw.setdefault("timeout_s", 5.0)
    return QueueCampaignLauncher(factory, queue, packs_dir=_packs(tmp_path), **kw)


def test_launch_enqueues_waits_and_returns_the_completed_campaign(db_factory, tmp_path):
    target_id = _verified_target(db_factory)
    queue = FakeQueue(db_factory)
    campaign_id = _launcher(db_factory, queue, tmp_path).launch(target_id, "alpha")
    assert queue.enqueued == [campaign_id] and queue.closed
    rec = CampaignRepo(db_factory).get(campaign_id)
    assert rec.status == "completed" and rec.target_id == target_id
    assert rec.policy.techniques == ["tech_a"]


def test_default_suite_is_every_pack_and_unknown_suite_is_refused(tmp_path):
    _packs(tmp_path)
    assert suite_techniques("default", tmp_path) == ["tech_a", "tech_b"]
    assert suite_techniques("beta", tmp_path) == ["tech_b"]
    for bad in ("nope", "../etc"):
        with pytest.raises(LaunchError):
            suite_techniques(bad, tmp_path)


def test_failed_candidate_campaign_is_an_error(db_factory, tmp_path):
    target_id = _verified_target(db_factory)
    with pytest.raises(LaunchError, match="ended failed"):
        _launcher(db_factory, FakeQueue(db_factory, final="failed"), tmp_path).launch(target_id, "alpha")


def test_timeout_cancels_the_run_and_raises(db_factory, tmp_path):
    target_id = _verified_target(db_factory)
    queue = FakeQueue(db_factory, never=True)
    launcher = _launcher(db_factory, queue, tmp_path, timeout_s=0.2)
    with pytest.raises(LaunchError, match="did not finish"):
        launcher.launch(target_id, "alpha")
    assert launcher.control.cancel_requested(queue.enqueued[0])


def test_timeout_with_failing_cancel_retries_once_then_marks_the_campaign_failed(
    db_factory, tmp_path, monkeypatch
):
    from cyberredteam.jobs.events import EventLog

    target_id = _verified_target(db_factory)
    queue = FakeQueue(db_factory, never=True)
    launcher = _launcher(db_factory, queue, tmp_path, timeout_s=0.2)
    attempts = []

    def broken(campaign_id, actor=None):
        attempts.append(campaign_id)
        raise RuntimeError("db down")

    monkeypatch.setattr(launcher.control, "request_cancel", broken)
    with pytest.raises(LaunchError, match="marked failed"):
        launcher.launch(target_id, "alpha")
    cid = queue.enqueued[0]
    assert len(attempts) == 3  # first try + one retry + the best-effort flag write when marking failed
    assert CampaignRepo(db_factory).get(cid).status == "failed"
    events = EventLog(db_factory).since(cid)
    assert events[-1].type == "campaign_failed" and events[-1].payload.message == "gate timeout"


def test_timeout_cancel_that_succeeds_on_retry_leaves_the_worker_to_finish(
    db_factory, tmp_path, monkeypatch
):
    target_id = _verified_target(db_factory)
    queue = FakeQueue(db_factory, never=True)
    launcher = _launcher(db_factory, queue, tmp_path, timeout_s=0.2)
    real, calls = launcher.control.request_cancel, []

    def flaky(campaign_id, actor=None):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("transient")
        real(campaign_id, actor)

    monkeypatch.setattr(launcher.control, "request_cancel", flaky)
    with pytest.raises(LaunchError, match="cancel requested"):
        launcher.launch(target_id, "alpha")
    assert launcher.control.cancel_requested(queue.enqueued[0])
    assert CampaignRepo(db_factory).get(queue.enqueued[0]).status != "failed"


def test_unverified_or_unknown_target_is_refused_and_nothing_is_enqueued(db_factory, tmp_path):
    store = SqlTargetStore(db_factory)
    unverified = store.create(make_target())
    queue = FakeQueue(db_factory)
    launcher = _launcher(db_factory, queue, tmp_path)
    with pytest.raises(LaunchError, match="not verified"):
        launcher.launch(unverified, "alpha")
    with pytest.raises(LaunchError, match="not found"):
        launcher.launch("00000000-0000-0000-0000-000000000000", "alpha")
    assert queue.enqueued == []


def test_production_target_gets_production_limits(db_factory, tmp_path):
    target_id = _verified_target(db_factory, environment="production")
    queue = FakeQueue(db_factory)
    campaign_id = _launcher(db_factory, queue, tmp_path).launch(target_id, "alpha")
    policy = CampaignRepo(db_factory).get(campaign_id).policy
    assert policy.max_parallel_conversations <= 2 and policy.max_total_requests <= 300
    assert policy.rate_limit_rps <= 1.0


def test_run_gate_maps_a_launch_error_to_a_gate_error(db_factory, tmp_path):
    target_id = _verified_target(db_factory)
    launcher = _launcher(db_factory, FakeQueue(db_factory, final="failed"), tmp_path)
    with pytest.raises(GateError, match="ended failed"):
        run_gate(CampaignRepo(db_factory), target_id=target_id, suite="alpha", baseline_id="b",
                 candidate_id=None, policy=GatePolicy(), launcher=launcher)
    time.sleep(0.1)


def test_timeout_path_never_overwrites_a_campaign_that_just_finished(db_factory, tmp_path):
    """Race: the worker finishes as completed, then the timeout path runs."""
    from cyberredteam.jobs.events import EventLog

    target_id = _verified_target(db_factory)
    queue = FakeQueue(db_factory, never=True)
    launcher = _launcher(db_factory, queue, tmp_path, timeout_s=5)
    cid = f"gate-{target_id[:6]}"
    repo = CampaignRepo(db_factory)
    from storage_v2_support import make_policy

    repo.create(cid, target_id, make_policy(), created_by="gate")
    repo.set_status(cid, "completed")
    launcher._mark_timed_out(cid)
    assert repo.get(cid).status == "completed"
    assert EventLog(db_factory).since(cid) == []  # no bogus campaign_failed event
    assert repo.set_status_if_not_terminal(cid, "failed") is False
    running = f"{cid}-r"
    repo.create(running, target_id, make_policy(), created_by="gate")
    repo.set_status(running, "running")
    assert repo.set_status_if_not_terminal(running, "failed") is True
    assert repo.get(running).status == "failed"
