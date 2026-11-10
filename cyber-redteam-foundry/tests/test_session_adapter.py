"""WP2: SessionAdapter against the stateful fake target (no network)."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
from fixtures.fake_target import DEFAULT_CANARY, DEFAULT_FORBIDDEN_TOOL, SAFE_REPLY, FakeTarget
from test_session_adapter_support import (
    CAMPAIGN,
    FakeClock,
    Recorder,
    make_adapter,
    make_config,
    run,
)

from cyberredteam.transport import SessionAdapter, TargetErrorKind

MODES = ["stateless_history", "server_session", "cookie"]


async def _converse(fake: FakeTarget, n: int, **cfg):
    adapter = make_adapter(fake.target_config(**cfg), fake.async_transport())
    async with adapter:
        return [await adapter.send(f"hello {i}") for i in range(n)]


@pytest.mark.parametrize("mode", MODES)
def test_multi_turn_in_every_mode(mode):
    fake = FakeTarget(profile="always_safe", session_mode=mode)
    results = run(_converse(fake, 4))
    assert all(r.error is None and r.http_status == 200 for r in results)
    assert [r.response_text for r in results] == [SAFE_REPLY] * 4
    # The fake only advances its turn counter if the adapter carries state.
    assert [r.attempts for r in results] == [1] * 4
    assert [rq.body.get("message") for rq in fake.requests] == [f"hello {i}" for i in range(4)]
    if mode == "stateless_history":
        assert len(fake.requests[3].body["messages"]) == 7
        assert fake.requests[3].body["messages"][-1] == {"role": "user", "content": "hello 3"}
    else:
        assert fake.sessions_issued == 1
        assert list(fake.sessions.values()) == [4]


def test_server_session_reuses_id():
    fake = FakeTarget(profile="session_server", session_mode="server_session")
    results = run(_converse(fake, 3))
    assert [r.response_text.endswith(f"(session turn {i})") for i, r in enumerate(results, 1)] == [True] * 3
    assert fake.sessions_issued == 1
    first_id = next(iter(fake.sessions))
    assert fake.requests[0].body["session_id"] is None
    assert fake.requests[1].body["session_id"] == first_id


def test_server_session_missing_id_is_error():
    rec = Recorder(lambda req, n: httpx.Response(200, json={"reply": "hi"}))
    cfg = make_config(
        session_mode="server_session", session_id_path="sid", response_path="reply",
        request_template='{"message": "{{MESSAGE}}", "sid": "{{SESSION_ID}}"}',
    )
    res = run(make_adapter(cfg, rec.transport).send("x"))
    assert res.error and res.error.kind is TargetErrorKind.EXTRACT_FAILED


def test_cookie_mode_uses_per_instance_jar():
    fake = FakeTarget(profile="always_safe", session_mode="cookie")

    async def go():
        a = make_adapter(fake.target_config(), fake.async_transport())
        b = make_adapter(fake.target_config(), fake.async_transport())
        await a.send("1"), await b.send("1"), await a.send("2")
        await a.aclose(), await b.aclose()

    run(go())
    assert fake.sessions_issued == 2
    assert sorted(fake.sessions.values()) == [1, 2]


def test_history_only_advances_on_success():
    fake = FakeTarget(profile="flaky_500", session_mode="stateless_history", fail_first=3)

    async def go():
        adapter = make_adapter(fake.target_config(), fake.async_transport())
        r1 = await adapter.send("a")  # 3 failures exhaust retries? attempts 1..3 -> error
        r2 = await adapter.send("b")
        return adapter, r1, r2

    adapter, r1, r2 = run(go())
    assert r1.error and r1.error.kind is TargetErrorKind.HTTP_5XX and r1.response_text == ""
    assert r2.error is None
    assert [m["content"] for m in adapter.history if m["role"] == "user"] == ["b"]


def test_default_body_without_template():
    rec = Recorder(lambda req, n: httpx.Response(200, json={"response": "ok"}))
    res = run(make_adapter(make_config(), rec.transport).send("hi there"))
    assert json.loads(rec.requests[0].content) == {"message": "hi there"}
    assert res.response_text == "ok"


def test_structural_substitution_handles_quotes_and_newlines():
    rec = Recorder(lambda req, n: httpx.Response(200, json={"response": "ok"}))
    cfg = make_config(request_template='{"input": {"q": "{{MESSAGE}}"}, "tags": ["x"]}')
    msg = 'say "hi"\n and {{HISTORY}} \\ done'
    run(make_adapter(cfg, rec.transport).send(msg))
    assert json.loads(rec.requests[0].content) == {"input": {"q": msg}, "tags": ["x"]}


def test_campaign_header_on_every_request():
    fake = FakeTarget(profile="always_safe", session_mode="server_session")
    run(_converse(fake, 3))
    assert [r.headers["x-canary-campaign"] for r in fake.requests] == [CAMPAIGN] * 3


# ── Extraction ───────────────────────────────────────────────────────────────


def _one(payload, **cfg):
    rec = Recorder(lambda req, n: httpx.Response(200, json=payload))
    return run(make_adapter(make_config(**cfg), rec.transport).send("q"))


def test_response_path_with_list_index():
    res = _one({"choices": [{"message": {"content": "deep"}}]}, response_path="choices.0.message.content")
    assert res.response_text == "deep" and res.error is None


@pytest.mark.parametrize("key", ["response", "output", "content", "text"])
def test_fallback_keys(key):
    assert _one({key: "fb"}).response_text == "fb"


def test_fallback_used_when_path_missing():
    assert _one({"text": "fb"}, response_path="nope.here").response_text == "fb"


def test_extract_failed_is_typed_not_stringified():
    res = _one({"unexpected": 1})
    assert res.error and res.error.kind is TargetErrorKind.EXTRACT_FAILED
    assert res.response_text == "" and "unexpected" not in res.response_text


def test_bad_json():
    rec = Recorder(lambda req, n: httpx.Response(200, content=b"<html>nope</html>"))
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert res.error and res.error.kind is TargetErrorKind.BAD_JSON and res.response_text == ""
    assert rec.requests and len(rec.requests) == 1


def test_hashes_bytes_latency():
    res = _one({"response": "ok"})
    assert len(res.request_hash) == 16 and len(res.response_hash) == 16
    assert res.response_bytes > 0 and res.latency_ms >= 0


# ── Tool calls ───────────────────────────────────────────────────────────────


def test_structured_tool_calls():
    fake = FakeTarget(profile="tool_misuse_on_turn_k", k=1)
    res = run(_converse(fake, 1))[0]
    names = [t.name for t in res.tool_calls]
    assert DEFAULT_FORBIDDEN_TOOL in names and len(names) == 2
    assert all(t.source == "structured" for t in res.tool_calls)
    assert res.tool_calls[1].call_id == "call-1-b"
    assert res.tool_calls[1].arguments == {"record_id": "placeholder-1"}


def test_structured_empty_when_path_set_but_no_calls():
    fake = FakeTarget(profile="always_safe")
    assert run(_converse(fake, 1))[0].tool_calls == []


def test_openai_style_tool_calls():
    payload = {"reply": "x", "tc": [{"id": "c1", "function": {"name": "f", "arguments": '{"a": 1}'}}]}
    res = _one(payload, response_path="reply", tool_trace_path="tc")
    assert res.tool_calls[0].name == "f" and res.tool_calls[0].arguments == {"a": 1}
    assert res.tool_calls[0].call_id == "c1"


def test_heuristic_tool_calls_without_trace_path():
    res = _one({"response": "I am calling employee_lookup now"})
    assert [t.name for t in res.tool_calls] == ["employee_lookup"]
    assert all(t.source == "heuristic" for t in res.tool_calls)


# ── Errors, retries ──────────────────────────────────────────────────────────


def test_flaky_500_retried_and_succeeds():
    fake = FakeTarget(profile="flaky_500", session_mode="stateless_history", fail_first=2)
    clock = FakeClock()
    adapter = make_adapter(fake.target_config(), fake.async_transport(), clock=clock)
    res = run(adapter.send("hi"))
    assert res.error is None and res.attempts == 3
    assert [r.status for r in fake.requests] == [500, 500, 200]
    assert clock.sleeps == [0.5, 1.0]


def test_5xx_exhausts_retries_max_two():
    rec = Recorder(lambda req, n: httpx.Response(500, json={"e": 1}))
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert len(rec.requests) == 3
    assert res.error and res.error.kind is TargetErrorKind.HTTP_5XX and res.http_status == 500


def test_2xx_never_retried_even_when_unparseable():
    for body in (b"not json", b'{"nothing": 1}'):
        rec = Recorder(lambda req, n, b=body: httpx.Response(200, content=b))
        res = run(make_adapter(make_config(), rec.transport).send("q"))
        assert len(rec.requests) == 1 and res.error is not None


def test_4xx_not_retried():
    rec = Recorder(lambda req, n: httpx.Response(404, json={"error": "nf"}))
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert len(rec.requests) == 1
    assert res.error and res.error.kind is TargetErrorKind.HTTP_4XX and res.response_text == ""


def test_connect_error_retried_then_unreachable():
    def handler(req, n):
        raise httpx.ConnectError("boom", request=req)

    rec = Recorder(handler)
    clock = FakeClock()
    res = run(make_adapter(make_config(), rec.transport, clock=clock).send("q"))
    assert len(rec.requests) == 3
    assert res.error and res.error.kind is TargetErrorKind.UNREACHABLE and res.response_text == ""


def test_connect_error_then_success():
    def handler(req, n):
        if n == 1:
            raise httpx.ConnectError("boom", request=req)
        return httpx.Response(200, json={"response": "ok"})

    rec = Recorder(handler)
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert res.error is None and res.response_text == "ok" and res.attempts == 2


def test_timeout_typed_and_not_retried():
    fake = FakeTarget(profile="slow", delay_s=5.0)
    cfg = fake.target_config(timeout_s=1)
    res = run(make_adapter(cfg, fake.async_transport()).send("q"))
    assert res.error and res.error.kind is TargetErrorKind.TIMEOUT
    assert res.response_text == "" and res.attempts == 1


def test_cancel_before_send():
    fake = FakeTarget(profile="always_safe")
    adapter = make_adapter(fake.target_config(), fake.async_transport())
    adapter.cancel()
    res = run(adapter.send("q"))
    assert res.error and res.error.kind is TargetErrorKind.CANCELLED
    assert fake.requests == [] and res.attempts == 0 and adapter.history == []


def test_leak_profile_text_passes_through():
    fake = FakeTarget(profile="leaks_after_n_turns", n_turns=1)
    results = run(_converse(fake, 2))
    assert DEFAULT_CANARY not in results[0].response_text
    assert DEFAULT_CANARY in results[1].response_text


def test_works_over_asgi_transport():
    fake = FakeTarget(profile="always_safe", session_mode="server_session")

    async def go():
        adapter = SessionAdapter(
            fake.target_config(),
            campaign_id=CAMPAIGN,
            rate_limiter=__import__("test_session_adapter_support").NoLimit(),
            transport=httpx.ASGITransport(app=fake.asgi_app()),
        )
        async with adapter:
            return [await adapter.send("a"), await adapter.send("b")]

    r1, r2 = run(go())
    assert r1.error is None and r2.error is None and fake.sessions_issued == 1


def test_no_secrets_in_logs_or_errors(caplog):
    secret = "s3cr3t-token-VALUE"
    cfg = make_config(auth={"type": "bearer", "token": secret})
    rec = Recorder(lambda req, n: httpx.Response(500, json={"echo": secret}))
    with caplog.at_level(logging.DEBUG):
        res = run(make_adapter(cfg, rec.transport).send("q"))
    assert rec.requests[0].headers["authorization"] == f"Bearer {secret}"
    assert secret not in caplog.text
    assert secret not in str(res.error) and secret not in repr(res)
