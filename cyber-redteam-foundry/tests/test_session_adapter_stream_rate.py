"""WP2: streaming assembly, Retry-After, and rate limiting."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
from test_session_adapter_support import (
    FakeClock,
    NoLimit,
    Recorder,
    bucket,
    make_adapter,
    make_config,
    run,
)

from cyberredteam.transport import InProcessTokenBucket, RateLimiter, TargetErrorKind
from cyberredteam.transport.session_adapter import parse_retry_after
from cyberredteam.transport.streaming import assemble_text, parse_ndjson, parse_sse

# ── Streaming ────────────────────────────────────────────────────────────────


def _sse(*events: str) -> bytes:
    return "".join(f"data: {e}\n\n" for e in events).encode()


def test_sse_openai_deltas_assembled():
    body = _sse(
        json.dumps({"choices": [{"delta": {"content": "Hel"}}]}),
        json.dumps({"choices": [{"delta": {"content": "lo"}}]}),
        json.dumps({"choices": [{"delta": {}}]}),
        "[DONE]",
    )
    rec = Recorder(lambda r, n: httpx.Response(200, content=body, headers={"content-type": "text/event-stream"}))
    res = run(make_adapter(make_config(streaming="sse"), rec.transport).send("q"))
    assert res.error is None and res.response_text == "Hello" and len(rec.requests) == 1


def test_sse_with_response_path_and_session_and_tools():
    body = _sse(
        json.dumps({"tok": "Hi ", "sid": "S1"}),
        json.dumps({"tok": "there", "tools": [{"name": "t1", "arguments": {}}]}),
    )
    rec = Recorder(lambda r, n: httpx.Response(200, content=body))
    cfg = make_config(
        streaming="sse", response_path="tok", session_mode="server_session",
        session_id_path="sid", tool_trace_path="tools",
        request_template='{"message": "{{MESSAGE}}", "sid": "{{SESSION_ID}}"}',
    )
    adapter = make_adapter(cfg, rec.transport)
    res = run(adapter.send("q"))
    assert res.response_text == "Hi there" and adapter.session_id == "S1"
    assert [t.name for t in res.tool_calls] == ["t1"]


def test_sse_plain_text_data_lines():
    assert assemble_text(parse_sse(_sse("one ", "two")), None) == "one two"


def test_ndjson_assembled():
    body = b'{"response": "a"}\n{"response": "b"}\n\n{"response": "c"}\n'
    rec = Recorder(lambda r, n: httpx.Response(200, content=body))
    res = run(make_adapter(make_config(streaming="ndjson", response_path="response"), rec.transport).send("q"))
    assert res.response_text == "abc"
    assert parse_ndjson(body)[0] == {"response": "a"}


def test_ndjson_invalid_line_is_bad_json():
    rec = Recorder(lambda r, n: httpx.Response(200, content=b'{"response": "a"}\nnot json\n'))
    res = run(make_adapter(make_config(streaming="ndjson"), rec.transport).send("q"))
    assert res.error and res.error.kind is TargetErrorKind.BAD_JSON


def test_stream_without_text_is_extract_failed():
    rec = Recorder(lambda r, n: httpx.Response(200, content=_sse(json.dumps({"meta": 1}))))
    res = run(make_adapter(make_config(streaming="sse"), rec.transport).send("q"))
    assert res.error and res.error.kind is TargetErrorKind.EXTRACT_FAILED and res.response_text == ""


# ── Retry-After ──────────────────────────────────────────────────────────────


def test_parse_retry_after_forms():
    assert parse_retry_after("3") == 3.0
    assert parse_retry_after("1.5") == 1.5
    assert parse_retry_after(None) is None and parse_retry_after("garbage") is None
    future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
    assert 25 <= parse_retry_after(future) <= 31
    past = format_datetime(datetime.now(timezone.utc) - timedelta(seconds=30), usegmt=True)
    assert parse_retry_after(past) == 0.0


def test_429_retry_after_honoured_then_success():
    def handler(req, n):
        if n == 1:
            return httpx.Response(429, json={}, headers={"Retry-After": "7"})
        return httpx.Response(200, json={"response": "ok"})

    rec = Recorder(handler)
    clock = FakeClock()
    res = run(make_adapter(make_config(), rec.transport, clock=clock).send("q"))
    assert res.error is None and clock.sleeps == [7.0] and len(rec.requests) == 2


def test_503_retry_after_honoured():
    def handler(req, n):
        if n == 1:
            return httpx.Response(503, json={}, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"response": "ok"})

    clock = FakeClock()
    res = run(make_adapter(make_config(), Recorder(handler).transport, clock=clock).send("q"))
    assert res.error is None and clock.sleeps == [2.0]


def test_429_gives_up_after_two_waits():
    rec = Recorder(lambda r, n: httpx.Response(429, json={}, headers={"Retry-After": "1"}))
    clock = FakeClock()
    res = run(make_adapter(make_config(), rec.transport, clock=clock).send("q"))
    assert len(rec.requests) == 3 and clock.sleeps == [1.0, 1.0]
    assert res.error and res.error.kind is TargetErrorKind.RATE_LIMITED and res.http_status == 429


def test_429_http_date_retry_after():
    when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=10), usegmt=True)

    def handler(req, n):
        if n == 1:
            return httpx.Response(429, json={}, headers={"Retry-After": when})
        return httpx.Response(200, json={"response": "ok"})

    clock = FakeClock()
    res = run(make_adapter(make_config(), Recorder(handler).transport, clock=clock).send("q"))
    assert res.error is None and 5 <= clock.sleeps[0] <= 11


# ── Rate limiter ─────────────────────────────────────────────────────────────


def test_token_bucket_is_a_rate_limiter():
    assert isinstance(InProcessTokenBucket(1.0), RateLimiter) and isinstance(NoLimit(), RateLimiter)


def test_token_bucket_spacing():
    clock = FakeClock()
    tb = bucket(2.0, clock)  # one request per 0.5s

    async def go():
        stamps = []
        for _ in range(4):
            await tb.acquire("t1")
            stamps.append(clock.now)
        return stamps

    stamps = run(go())
    gaps = [round(b - a, 6) for a, b in zip(stamps, stamps[1:])]
    assert gaps == [0.5, 0.5, 0.5]


def test_token_bucket_burst_and_independent_targets():
    clock = FakeClock()
    tb = bucket(1.0, clock, burst=3)

    async def go():
        for _ in range(3):
            await tb.acquire("a")
        immediate = clock.sleeps[:]
        await tb.acquire("b")  # different target: its own bucket
        return immediate, clock.sleeps[:]

    immediate, after_b = run(go())
    assert immediate == [] and after_b == []


def test_shared_bucket_spaces_concurrent_adapters():
    clock = FakeClock()
    tb = bucket(1.0, clock)
    cfg = make_config()
    rec = Recorder(lambda r, n: httpx.Response(200, json={"response": "ok"}))
    stamps: list[float] = []
    inner = rec.transport

    def stamp(request, n=None):  # record fake time at each wire request
        stamps.append(clock.now)

    orig = rec._handler
    rec._handler = lambda req, n: (stamp(req), orig(req, n))[1]

    async def go():
        adapters = [make_adapter(cfg, inner, clock=clock, limiter=tb) for _ in range(3)]
        await asyncio.gather(*(a.send("q") for a in adapters))

    run(go())
    assert [round(b - a, 6) for a, b in zip(stamps, stamps[1:])] == [1.0, 1.0]


def test_each_retry_acquires_a_token():
    acquired: list[str] = []

    class Counting:
        async def acquire(self, target_id: str) -> None:
            acquired.append(target_id)

        async def penalize(self, target_id: str, seconds: float) -> None:
            return None

    def handler(req, n):
        return httpx.Response(500 if n == 1 else 200, json={"response": "ok"})

    cfg = make_config()
    res = run(make_adapter(cfg, Recorder(handler).transport, limiter=Counting()).send("q"))
    assert res.error is None and acquired == [cfg.target_id] * 2
