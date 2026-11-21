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
