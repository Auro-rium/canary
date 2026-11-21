# ruff: noqa: F811  (pytest fixtures imported from engine_support)
"""WP3 campaign fan-out: semaphore cap, kill switch, resume/idempotency."""

from __future__ import annotations

import asyncio
from collections import Counter

import pytest
from engine_support import _key, build, factory, new_campaign_id  # noqa: F401
from fixtures.fake_target import FakeTarget

from cyberredteam.engine import plan_conversations, run_campaign
from cyberredteam.storage.v2.repositories import CampaignRepo


def test_plan_is_techniques_times_trials_never_truncated(factory):
    h = build(factory, techniques=[f"t{i}" for i in range(13)], trials_per_technique=7)
    specs = plan_conversations(h.request, "c1")
    assert len(specs) == 91
    assert len({s.conversation_id for s in specs}) == 91
    # Deterministic ids: the same campaign plans the same conversations.
    assert [s.conversation_id for s in specs] == [
        s.conversation_id for s in plan_conversations(h.request, "c1")
    ]
    assert specs[0].conversation_id != plan_conversations(h.request, "c2")[0].conversation_id


@pytest.mark.parametrize("cap", [1, 3])
def test_semaphore_caps_parallel_conversations(factory, cap):
    h = build(factory, techniques=["a", "b", "c"], trials_per_technique=3, max_turns=3,
              max_parallel_conversations=cap)
    outcome = asyncio.run(run_campaign(h.request, new_campaign_id(), h.deps))
    assert len(outcome.conversations) == 9
    assert all(c.status == "completed" and c.turns == 3 for c in outcome.conversations)
    assert h.max_active == cap


def test_kill_switch_stops_ten_parallel_conversations_within_one_turn(factory):
    h = build(factory, techniques=["a", "b"], trials_per_technique=5, max_turns=8,
              max_parallel_conversations=10)
    campaign = new_campaign_id()
    at_kill: dict[str, int] = {}
    seen: Counter[str] = Counter()

    async def on_event(event_type, payload):
        if event_type != "turn":
            return
        seen[payload.conversation_id] += 1
        if sum(seen.values()) == 15 and not at_kill:
            at_kill.update(seen)
            await h.control.kill_all()

    h.events.hook = on_event
    outcome = asyncio.run(run_campaign(h.request, campaign, h.deps))

    assert outcome.status == "killed"
    assert len(outcome.conversations) == 10
    assert {c.status for c in outcome.conversations} == {"stopped_killed"}
    for conv in outcome.conversations:
        persisted = len(h.conversations.get(conv.conversation_id).turns)
        assert persisted <= at_kill.get(conv.conversation_id, 0) + 1
        assert persisted < 8
    assert CampaignRepo(factory).get(campaign).status == "cancelled"
    assert h.events.of_type("campaign_cancelled")[0].reason == "kill_switch"


def test_kill_before_start_sends_nothing(factory):
    h = build(factory, techniques=["a"], trials_per_technique=3)
    asyncio.run(h.control.kill_all())
    outcome = asyncio.run(run_campaign(h.request, new_campaign_id(), h.deps))
    assert {c.status for c in outcome.conversations} == {"stopped_killed"}
    assert h.fake.requests == []


@pytest.mark.parametrize("mode", ["stateless_history", "server_session"])
def test_resume_after_interrupt_no_duplicates_terminal_skipped(factory, mode):
    profile = "session_server" if mode == "server_session" else "always_safe"
    fake = FakeTarget(profile=profile, session_mode=mode)
    campaign = new_campaign_id()

    # Run 1: two conversations, one at a time, interrupted mid-way through the second.
    h1 = build(factory, fake=fake, techniques=["a"], trials_per_technique=2, max_turns=3,
               max_parallel_conversations=1)
    turn_events = 0

    async def main():
        task = asyncio.current_task()

        def on_event(event_type, payload):
            nonlocal turn_events
            if event_type == "turn":
                turn_events += 1
                if turn_events == 5:
                    task.cancel()

        h1.events.hook = on_event
        await run_campaign(h1.request, campaign, h1.deps)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(main())

    specs = plan_conversations(h1.request, campaign)
    first, second = (h1.conversations.get(s.conversation_id) for s in specs)
    assert first.status == "completed" and len(first.turns) == 3
    assert second.status == "running" and len(second.turns) == 2
    requests_before = len(fake.requests)

    # Run 2 (a "restarted worker"): same campaign id, fresh deps.
    h2 = build(factory, fake=fake, techniques=["a"], trials_per_technique=2, max_turns=3,
               max_parallel_conversations=1)
    h2.request = h1.request  # same target row
    outcome = asyncio.run(run_campaign(h1.request, campaign, h2.deps))

    by_id = {c.conversation_id: c for c in outcome.conversations}
    assert by_id[first.conversation_id].skipped
    assert by_id[second.conversation_id].resumed
    assert outcome.status == "completed"
    # Exactly one more turn was sent: no turn was repeated.
    assert len(fake.requests) == requests_before + 1
    resumed = h2.conversations.get(second.conversation_id, raw=True, actor="test")
    assert resumed.status == "completed"
    assert [t.index for t in resumed.turns] == [0, 1, 2]
    assert [t.message for t in resumed.turns] == ["hello turn 0", "hello turn 1", "hello turn 2"]
    # The planner was given the persisted raw transcript.
    assert len(h2.planners[0].states[0].turns) == 2
    last = fake.requests[-1].body
    if mode == "stateless_history":
        assert [m["content"] for m in last["messages"] if m["role"] == "user"] == [
            "hello turn 0", "hello turn 1", "hello turn 2"
        ]
    else:
        assert last["session_id"] == resumed.target_session_ref
        assert fake.sessions_issued == 2  # one per conversation, none re-opened

    # Run 3: everything terminal, nothing is sent.
    h3 = build(factory, fake=fake, techniques=["a"], trials_per_technique=2, max_turns=3)
    again = asyncio.run(run_campaign(h1.request, campaign, h3.deps))
    assert all(c.skipped for c in again.conversations)
    assert len(fake.requests) == requests_before + 1


def test_rerun_restores_budget_from_ledger(factory):
    h = build(factory, techniques=["a"], trials_per_technique=2, max_turns=3,
              max_total_requests=4, max_parallel_conversations=1)
    campaign = new_campaign_id()
    first = asyncio.run(run_campaign(h.request, campaign, h.deps))
    assert first.requests_used == 4
    assert sorted(c.status for c in first.conversations) == ["completed", "stopped_budget"]
    h2 = build(factory, techniques=["a"], trials_per_technique=2, max_turns=3,
               max_total_requests=4, max_parallel_conversations=1)
    second = asyncio.run(run_campaign(h.request, campaign, h2.deps))
    assert second.requests_used == 4
    assert all(c.skipped for c in second.conversations)
