"""WP2 review fixes: never re-send after a status line, byte cap, deadline,
Responses-API streams, penalize, redirects, serialization."""

from __future__ import annotations

import asyncio
import json

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

from cyberredteam.transport import TargetErrorKind
from cyberredteam.transport.session_adapter import MAX_RESPONSE_BYTES
from cyberredteam.transport.streaming import assemble_text, parse_sse


class _BrokenBody(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b'{"response": "par'
        raise httpx.ReadError("mid-body")


def test_2xx_with_mid_body_failure_is_not_resent():
    rec = Recorder(lambda r, n: httpx.Response(200, stream=_BrokenBody()))
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert len(rec.requests) == 1
    assert res.error and res.error.kind is TargetErrorKind.UNREACHABLE and res.response_text == ""


def test_read_error_before_response_not_retried():
    def handler(req, n):
        raise httpx.ReadError("x", request=req)

    rec = Recorder(handler)
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert len(rec.requests) == 1 and res.error.kind is TargetErrorKind.UNREACHABLE


def test_pool_timeout_retried():
    def handler(req, n):
        if n == 1:
            raise httpx.PoolTimeout("p", request=req)
        return httpx.Response(200, json={"response": "ok"})

    rec = Recorder(handler)
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert res.error is None and len(rec.requests) == 2


class _Trickle(httpx.AsyncByteStream):
    async def __aiter__(self):
        while True:
            yield b" "
            await asyncio.sleep(0.01)


def test_trickling_body_hits_overall_deadline():
    rec = Recorder(lambda r, n: httpx.Response(200, stream=_Trickle()))
    adapter = make_adapter(make_config(), rec.transport)
    adapter._deadline_s = 0.1
    res = run(adapter.send("q"))
    assert len(rec.requests) == 1
    assert res.error and res.error.kind is TargetErrorKind.TIMEOUT


def test_oversized_body_rejected():
    big = b'{"response": "' + b"a" * (MAX_RESPONSE_BYTES + 10) + b'"}'
    rec = Recorder(lambda r, n: httpx.Response(200, content=big))
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert len(rec.requests) == 1 and res.response_text == ""
    assert res.error and res.error.kind is TargetErrorKind.RESPONSE_TOO_LARGE


def test_redirect_is_its_own_kind_and_not_retried():
    rec = Recorder(lambda r, n: httpx.Response(302, headers={"location": "http://elsewhere.test/"}))
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert len(rec.requests) == 1
    assert res.error and res.error.kind is TargetErrorKind.HTTP_REDIRECT


def test_deeply_nested_json_is_bad_json():
    rec = Recorder(lambda r, n: httpx.Response(200, content=b"[" * 100000 + b"]" * 100000))
    res = run(make_adapter(make_config(), rec.transport).send("q"))
    assert res.error and res.error.kind is TargetErrorKind.BAD_JSON


def test_concurrent_sends_serialize():
    active = {"now": 0, "max": 0}

    class Slow(httpx.AsyncByteStream):
        async def __aiter__(self):
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
            await asyncio.sleep(0.01)
            active["now"] -= 1
            yield b'{"response": "ok"}'

    rec = Recorder(lambda r, n: httpx.Response(200, stream=Slow()))
    adapter = make_adapter(make_config(), rec.transport)

    async def go():
        return await asyncio.gather(adapter.send("a"), adapter.send("b"), adapter.send("c"))

    results = run(go())
    assert all(r.error is None for r in results) and active["max"] == 1
    assert [m["content"] for m in adapter.history if m["role"] == "user"] == ["a", "b", "c"]


# ── Retry-After / penalize ───────────────────────────────────────────────────


def test_retry_after_longer_than_timeout_returns_rate_limited_immediately():
    rec = Recorder(lambda r, n: httpx.Response(429, json={}, headers={"Retry-After": "9999"}))
    clock = FakeClock()
    res = run(make_adapter(make_config(timeout_s=10), rec.transport, clock=clock).send("q"))
    assert len(rec.requests) == 1 and clock.sleeps == []
    assert res.error and res.error.kind is TargetErrorKind.RATE_LIMITED


def test_penalize_called_on_limiter():
    rl = NoLimit()

    def handler(req, n):
        return httpx.Response(
            429 if n == 1 else 200, json={"response": "ok"}, headers={"Retry-After": "2"}
        )

    cfg = make_config()
    run(make_adapter(cfg, Recorder(handler).transport, limiter=rl).send("q"))
    assert rl.penalties == [(cfg.target_id, 2.0)]


def test_penalty_holds_other_callers_of_the_shared_bucket():
    clock = FakeClock()
    tb = bucket(100.0, clock)
    cfg = make_config()

    async def go():
        await tb.penalize(cfg.target_id, 5.0)
        before = clock.now
        await tb.acquire(cfg.target_id)
        waited = clock.now - before
        await tb.acquire("other-target")
        return waited

    assert run(go()) >= 5.0


# ── Responses-API style streams ─────────────────────────────────────────────


def _sse(*events: dict) -> bytes:
    return "".join(f"data: {json.dumps(e)}\n\n" for e in events).encode()


def _responses_sse() -> bytes:
    evs = [{"type": "response.created", "response": {"id": "r"}}]
    evs += [{"type": "response.output_text.delta", "delta": d} for d in ("Hel", "lo ", "world")]
    evs += [
        {"type": "response.output_text.done", "text": "Hello world"},
        {"type": "response.completed", "response": {"id": "r", "output": []}},
    ]
    return _sse(*evs)


def test_responses_api_stream_not_duplicated():
    for path in (None, "delta"):
        body = _responses_sse()
        rec = Recorder(lambda r, n, b=body: httpx.Response(200, content=b))
        cfg = make_config(streaming="sse", response_path=path)
        res = run(make_adapter(cfg, rec.transport).send("q"))
        assert res.error is None and res.response_text == "Hello world", path


def test_response_path_ignores_fallback_paths():
    body = _sse({"tok": "A", "text": "X"}, {"text": "Y"})
    assert assemble_text(parse_sse(body), "tok") == "A"
