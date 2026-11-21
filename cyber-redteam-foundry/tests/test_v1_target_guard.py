"""The v1 flow (SessionTargetAdapter) is held to the same guards as v2."""

from __future__ import annotations

import pytest

from cyberredteam.jobs.control import ControlStore
from cyberredteam.tools.target_adapter import SessionTargetAdapter, V1TargetRefused
from v1_guard_support import FakeClock, build, make_transport, register, v1_store  # noqa: F401


def test_private_host_refused_before_any_send(v1_store):
    seen: list = []
    adapter = build(v1_store, "http://10.0.0.5/chat", seen, local=False)
    text, _ = adapter.execute_attack("hi")
    assert seen == []
    assert "target refused" in text
    assert adapter.last_observation["status"] == "cancelled"


def test_loopback_host_refused_before_any_send(v1_store):
    seen: list = []
    adapter = build(v1_store, "http://127.0.0.1:9000/chat", seen, local=False)
    adapter.execute_attack("hi")
    assert seen == []


def test_metadata_host_refused_before_any_send(v1_store):
    seen: list = []
    adapter = build(v1_store, "http://169.254.169.254/latest/meta-data", seen, local=False)
    text, _ = adapter.execute_attack("hi")
    assert seen == []
    assert "target refused" in text


def test_unverified_target_refused(v1_store):
    register(v1_store, "https://agent.example.com/chat", verified=False)
    with pytest.raises(V1TargetRefused, match="not verified"):
        SessionTargetAdapter("https://agent.example.com/chat", store=v1_store)


def test_unregistered_raw_url_refused(v1_store):
    with pytest.raises(V1TargetRefused, match="not a registered target"):
        SessionTargetAdapter("https://agent.example.com/chat", store=v1_store)


def test_lookup_by_target_id_and_forged_verified_is_not_possible(v1_store):
    seen: list = []
    cfg = register(v1_store, "https://agent.example.com/chat")
    adapter = SessionTargetAdapter(
        cfg.target_id, store=v1_store, transport=make_transport({"response": "ok"}, seen),
        ownership_options={"resolve_host": lambda h: ["93.184.216.34"]},
    )
    assert adapter._config.verified is True
    assert adapter.execute_attack("hi")[0] == "ok"
    assert seen[0].headers["x-canary-campaign"]


def test_allowed_targets_only_narrows(v1_store, monkeypatch):
    register(v1_store, "https://agent.example.com/chat")
    monkeypatch.setenv("ALLOWED_TARGETS", "https://other.example.com/chat")
    with pytest.raises(V1TargetRefused, match="ALLOWED_TARGETS"):
        SessionTargetAdapter("https://agent.example.com/chat", store=v1_store)


def test_two_sequential_attacks_are_rate_limited(v1_store):
    seen: list = []
    clock = FakeClock()
    adapter = build(v1_store, "http://localhost:9000/chat", seen, clock=clock, sleep=clock.sleep)
    adapter.execute_attack("one")
    adapter.execute_attack("two")
    assert len(seen) == 2
    assert clock.sleeps == [pytest.approx(1.0)]


def test_production_target_capped_at_one_rps(v1_store):
    seen: list = []
    clock = FakeClock()
    adapter = build(v1_store, "http://localhost:9001/chat", seen, environment="production",
                    rate_limit_rps=50.0, clock=clock, sleep=clock.sleep)
    adapter.execute_attack("one")
    adapter.execute_attack("two")
    assert clock.sleeps == [pytest.approx(1.0)]


def test_env_kill_switch_stops_sends(v1_store, monkeypatch):
    seen: list = []
    adapter = build(v1_store, "http://localhost:9000/chat", seen)
    monkeypatch.setenv("CANARY_KILL_SWITCH", "1")
    text, _ = adapter.execute_attack("hi")
    assert seen == [] and "kill switch" in text


def test_db_kill_switch_stops_sends(v1_store):
    seen: list = []
    adapter = build(v1_store, "http://localhost:9000/chat", seen)
    adapter.execute_attack("ok first")
    assert len(seen) == 1
    ControlStore(v1_store.factory).set_kill_switch(True, "tester")
    text, _ = adapter.execute_attack("hi")
    assert len(seen) == 1 and "kill switch" in text
