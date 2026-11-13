"""SessionAdapter.restore(): seeding a fresh adapter for engine resume (WP3)."""

from __future__ import annotations

import pytest
from fixtures.fake_target import FakeTarget
from test_session_adapter_support import make_adapter, run


def test_restore_history_is_sent_as_history_on_next_turn():
    fake = FakeTarget(session_mode="stateless_history")
    adapter = make_adapter(fake.target_config(), fake.transport())
    adapter.restore([
        {"role": "user", "content": "hello turn 0"},
        {"role": "assistant", "content": "reply 0"},
    ])

    async def go():
        async with adapter:
            return await adapter.send("hello turn 1")

    result = run(go())
    assert result.ok
    body = fake.requests[-1].body
    assert [m["content"] for m in body["messages"]] == ["hello turn 0", "reply 0", "hello turn 1"]
    assert fake.requests[-1].headers["x-canary-campaign"]


def test_restore_session_id_continues_server_session():
    fake = FakeTarget(profile="session_server", session_mode="server_session")
    first = make_adapter(fake.target_config(), fake.transport())

    async def go():
        async with first:
            await first.send("hello turn 0")
        sid = first.session_id
        second = make_adapter(fake.target_config(), fake.transport())
        second.restore([], session_id=sid)
        async with second:
            return sid, await second.send("hello turn 1")

    sid, result = run(go())
    assert result.ok
    assert fake.requests[-1].body["session_id"] == sid
    assert fake.sessions_issued == 1
    assert "session turn 2" in result.response_text


def test_restore_rejected_after_use_and_on_bad_history():
    fake = FakeTarget()
    adapter = make_adapter(fake.target_config(), fake.transport())
    with pytest.raises(ValueError):
        adapter.restore([{"role": "system", "content": "x"}])
    run(adapter.send("hello"))
    with pytest.raises(RuntimeError):
        adapter.restore([])
    run(adapter.aclose())
