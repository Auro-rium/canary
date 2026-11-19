"""WP7 wiring against WP3's final engine API, through ``execute_campaign``.

* ``CampaignRefused`` (engine start checks, or the same check at load time) is a
  terminal ``refused`` job outcome: campaign ``failed``, one ``campaign_failed``
  event, no HTTP request, heartbeat released, never resumed.
* Production limits run through the real wiring (shared limiter, default-style
  adapter with ``before_attempt``), every request carries ``X-Canary-Campaign``.
* The budget is charged per HTTP request.
* The target's auth secret never reaches logs, events, audit rows or the outcome.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import pytest
from engine_support import ScriptedPlanner, build, new_campaign_id
from fixtures.fake_target import FakeTarget
from sqlalchemy import update

from cyberredteam.contracts import CampaignPolicy, CampaignRequest, parse_sse_event
from cyberredteam.jobs import execution
from cyberredteam.jobs.control import DbRunControl
from cyberredteam.jobs.events import SECRET_MASK
from cyberredteam.jobs.execution import JobRuntime, execute_campaign
from cyberredteam.jobs.queue import InProcessQueue
from cyberredteam.jobs.resume import HeartbeatRepo, reap_stale
from cyberredteam.jobs.runner_wiring import SharedLimiters, auth_secret_values, make_runner
from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.repositories import (
    AuditRepo,
    CampaignRepo,
    ConversationRepo,
    SqlTargetStore,
)
from cyberredteam.transport.session_adapter import CAMPAIGN_HEADER

SECRET = "zq7-UNIQUE-hdr-value-4f9c1"  # matches no redaction pattern on purpose
AUTH = {"type": "header", "header_name": "X-Api-Key", "value": SECRET}


@dataclass
class EchoingTarget(FakeTarget):
    """Echoes the caller's own API key back in every reply."""

    def _reply(self, turn: int) -> str:
        return f"Sure. Your key is {SECRET} (turn {turn})"


def _setup(factory, *, fake=None, environment="staging", real_limiter=False, **policy):
    fake = fake or FakeTarget(required_headers={"X-Api-Key": SECRET})
    h = build(
        factory, fake=fake, target_overrides={"environment": environment, "auth": AUTH}, **policy
    )
    SqlTargetStore(factory).set_verified(h.request.target.target_id, "header")
    cid = new_campaign_id()
    CampaignRepo(factory).create(cid, h.request.target.target_id, h.request.policy)
    rt = JobRuntime(factory=factory, runner=None, control=DbRunControl(factory),
                    heartbeat_interval_s=0.05)
    options = {"adapter_factory": h.deps.adapter_factory, "clock": h.deps.clock}
    if not real_limiter:
        options["rate_limiter"] = h.deps.rate_limiter
    rt.runner = make_runner(rt, lambda spec: ScriptedPlanner(), engine_options=options)
    return rt, cid, h


def _event_texts(rt, cid):
    return [e.to_sse() for e in rt.events.since(cid)]


def _assert_no_secret(rt, cid, caplog, *extra):
    assert SECRET not in caplog.text
    for text in _event_texts(rt, cid):
        assert SECRET not in text
    for row in AuditRepo(rt.factory).list():
        assert SECRET not in repr(row)
    for value in extra:
        assert SECRET not in repr(value)


# ── CampaignRefused: terminal "refused" ──────────────────────────────────────

FORGERIES = {
    "rps_over_limit": lambda r: CampaignRequest.model_construct(
        target=r.target, policy=r.policy.model_copy(update={"rate_limit_rps": 5.0})),
    "parallel_over_limit": lambda r: CampaignRequest.model_construct(
        target=r.target, policy=r.policy.model_copy(update={"max_parallel_conversations": 3})),
    "total_over_limit": lambda r: CampaignRequest.model_construct(
        target=r.target, policy=r.policy.model_copy(update={"max_total_requests": 301})),
    "unverified_target": lambda r: CampaignRequest.model_construct(
        target=r.target.model_copy(update={"verified": False}), policy=r.policy),
    "nan_rate": lambda r: CampaignRequest.model_construct(
        target=r.target, policy=r.policy.model_copy(update={"rate_limit_rps": float("nan")})),
}


@pytest.mark.parametrize("forgery", sorted(FORGERIES))
def test_engine_refusal_is_terminal_refused(db_factory, caplog, forgery):
    caplog.set_level(logging.DEBUG)
    rt, cid, h = _setup(db_factory, environment="production", max_parallel_conversations=2,
                        max_total_requests=300)
    real = rt.runner
    calls = []

    async def forging_runner(request, campaign_id):
        calls.append(campaign_id)
        return await real(FORGERIES[forgery](request), campaign_id)

    rt.runner = forging_runner
    outcome = asyncio.run(execute_campaign(rt, cid))
    assert outcome == "refused"
    assert calls == [cid]  # called once, not retried
    assert CampaignRepo(db_factory).get(cid).status == "failed"
    events = rt.events.since(cid)
    assert [e.type for e in events] == ["campaign_failed"]  # no campaign_started
    assert events[0].payload.message.startswith("CampaignRefused:")
    assert h.fake.requests == []  # nothing was sent
    assert ConversationRepo(db_factory).list_for_campaign(cid) == []
    assert HeartbeatRepo(db_factory).get(cid) is None
    assert AuditRepo(db_factory).list(action="campaign.refused")
    # terminal: never resumed, re-delivery is a no-op
    queue = InProcessQueue()
    asyncio.run(reap_stale(db_factory, queue, stale_after_s=0))
    assert queue.enqueued == []
    assert asyncio.run(execute_campaign(rt, cid)) == "skipped"
    _assert_no_secret(rt, cid, caplog, outcome)


def test_load_time_refusal_of_stored_policy_over_production_limits(db_factory, caplog):
    caplog.set_level(logging.DEBUG)
    rt, cid, h = _setup(db_factory, environment="production", max_parallel_conversations=2,
                        max_total_requests=300)
    forged = CampaignPolicy.model_construct(**{**h.request.policy.model_dump(), "rate_limit_rps": 5.0})
    cid2 = new_campaign_id()
    CampaignRepo(db_factory).create(cid2, h.request.target.target_id, forged)
    called = []

    async def runner(request, campaign_id):
        called.append(campaign_id)

    rt.runner = runner
    assert asyncio.run(execute_campaign(rt, cid2)) == "refused"
    assert called == []  # refused before the campaign was marked running
    assert CampaignRepo(db_factory).get(cid2).status == "failed"
    events = rt.events.since(cid2)
    assert [e.type for e in events] == ["campaign_failed"]
    assert events[0].payload.message == "CampaignRefused: campaign request rejected (ValidationError)"
    assert not AuditRepo(db_factory).list(action="campaign.resumed")
    assert HeartbeatRepo(db_factory).get(cid2) is None
    _assert_no_secret(rt, cid2, caplog)


def test_unverified_target_is_refused_at_load(db_factory):
    rt, cid, h = _setup(db_factory)
    with db_factory() as s:
        s.execute(update(orm.TargetRow)
                  .where(orm.TargetRow.target_id == h.request.target.target_id)
                  .values(verified=False))
        s.commit()
    assert asyncio.run(execute_campaign(rt, cid)) == "refused"
    ev = rt.events.since(cid)
    assert ev[-1].payload.message == "CampaignRefused: target is not verified"
    assert h.fake.requests == []


def test_load_request_returns_normalised_copy(db_factory):
    rt, cid, h = _setup(db_factory)
    req = execution.load_request(rt, cid)
    assert type(req) is CampaignRequest and req.target.verified is True
    assert req.target.auth.value.get_secret_value() == SECRET  # secrets survive normalisation


# ── Production limits, header, budget through the real wiring ───────────────


def test_production_run_at_limits_with_shared_limiter_and_campaign_header(db_factory):
    rt, cid, h = _setup(
        db_factory, environment="production", real_limiter=True, techniques=["a", "b"],
        max_turns=1, rate_limit_rps=1.0, max_parallel_conversations=2, max_total_requests=300,
    )
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    assert h.max_active <= 2
    assert len(h.fake.requests) == 2
    assert all(r.headers.get(CAMPAIGN_HEADER.lower()) == cid for r in h.fake.requests)
    assert all(r.headers.get("x-api-key") == SECRET for r in h.fake.requests)


def test_budget_is_charged_per_http_request(db_factory):
    rt, cid, h = _setup(db_factory, techniques=["a", "b"], max_turns=5, max_total_requests=3)
    assert asyncio.run(execute_campaign(rt, cid)) == "completed"
    assert len(h.fake.requests) <= 3
    convs = ConversationRepo(db_factory)
    statuses = {convs.get(i).status for i in convs.list_for_campaign(cid)}
    assert "stopped_budget" in statuses


def test_shared_limiters_one_per_target_and_never_loosened():
    limiters = SharedLimiters()
    fake = FakeTarget()
    t1, t2 = fake.target_config(), fake.target_config()
    slow = CampaignPolicy(techniques=["a"], rate_limit_rps=0.5)
    fast = CampaignPolicy(techniques=["a"], rate_limit_rps=5.0)
    a = limiters(t1, slow)
    assert limiters(t1, fast) is a and a.rps == 0.5  # a higher rps never loosens
    b = limiters(t2, fast)
    assert b is not a and b.rps == 5.0
    assert limiters(t2, slow) is b and b.rps == 0.5  # a lower rps tightens for all holders


def test_auth_secret_values():
    fake = FakeTarget()
    assert auth_secret_values(fake.target_config(auth=AUTH)) == (SECRET,)
    assert auth_secret_values(fake.target_config()) == ()


# ── Secrets never reach logs or events ───────────────────────────────────────


@dataclass
class CutEchoTarget(FakeTarget):
    """Echoes the key so that the 280-char preview cut falls inside it."""

    def _reply(self, turn: int) -> str:
        return "x" * 268 + SECRET + " tail"


def test_secret_split_by_the_preview_cut_is_masked(db_factory, caplog):
    rt, cid, h = _setup(db_factory, fake=CutEchoTarget(required_headers={"X-Api-Key": SECRET}),
                        techniques=["a"], max_turns=1)
    asyncio.run(execute_campaign(rt, cid))
    turns = [e for e in rt.events.since(cid) if e.type == "turn"]
    assert turns
    texts = _event_texts(rt, cid)
    for k in range(4, len(SECRET) + 1):
        for i in range(len(SECRET) - k + 1):
            assert not any(SECRET[i:i + k] in t for t in texts)


def test_echoed_auth_secret_never_reaches_logs_events_or_audit(db_factory, caplog):
    caplog.set_level(logging.DEBUG)
    fake = EchoingTarget(required_headers={"X-Api-Key": SECRET})
    rt, cid, h = _setup(db_factory, fake=fake, techniques=["a"], max_turns=2)
    outcome = asyncio.run(execute_campaign(rt, cid))
    assert h.fake.successful_requests()  # the target really echoed the key
    turns = [e for e in rt.events.since(cid) if e.type == "turn"]
    assert turns and all(SECRET_MASK in e.payload.response_preview for e in turns)
    for text in _event_texts(rt, cid):  # and the stored form round-trips the contract
        parse_sse_event(text.split("data: ", 1)[1].strip())
    _assert_no_secret(rt, cid, caplog, outcome)
