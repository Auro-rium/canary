"""WP2: SessionAdapter auth strategies."""

from __future__ import annotations

import logging

import httpx
from fixtures.fake_target import FakeTarget
from test_session_adapter_support import FakeClock, Recorder, make_adapter, make_config, run

from cyberredteam.transport import TargetErrorKind

OK = {"response": "ok"}


def test_none_sends_no_auth_headers():
    rec = Recorder(lambda r, n: httpx.Response(200, json=OK))
    run(make_adapter(make_config(), rec.transport).send("q"))
    assert "authorization" not in rec.requests[0].headers


def test_bearer_against_fake_required_headers():
    fake = FakeTarget(required_headers={"Authorization": "Bearer tok-1"})
    cfg = fake.target_config(auth={"type": "bearer", "token": "tok-1"})
    res = run(make_adapter(cfg, fake.async_transport()).send("hi"))
    assert res.error is None

    bad = fake.target_config(auth={"type": "bearer", "token": "wrong"})
    res = run(make_adapter(bad, fake.async_transport()).send("hi"))
    assert res.error and res.error.kind is TargetErrorKind.HTTP_4XX and res.http_status == 401


def test_custom_header_auth():
    fake = FakeTarget(required_headers={"X-Api-Key": "k-123"})
    cfg = fake.target_config(auth={"type": "header", "header_name": "X-Api-Key", "value": "k-123"})
    assert run(make_adapter(cfg, fake.async_transport()).send("hi")).error is None


def _oauth_handler(expires_in=3600, tokens=None):
    issued: list[str] = []

    def handler(req: httpx.Request, n: int) -> httpx.Response:
        if req.url.path == "/token":
            tok = f"tok-{len(issued) + 1}"
            issued.append(tok)
            return httpx.Response(200, json={"access_token": tok, "expires_in": expires_in})
        if req.headers.get("authorization") not in {f"Bearer {t}" for t in (tokens or issued[-1:])}:
            return httpx.Response(401, json={"e": "expired"})
        return httpx.Response(200, json=OK)

    return handler, issued


OAUTH = {
    "type": "oauth_client_credentials",
    "token_url": "http://fake-target.test/token",
    "client_id": "cid",
    "client_secret": "csecret",
    "scope": "chat",
}


def test_oauth_fetches_once_and_caches():
    handler, issued = _oauth_handler()
    rec = Recorder(handler)
    adapter = make_adapter(make_config(auth=OAUTH), rec.transport)

    async def go():
        return [await adapter.send("a"), await adapter.send("b")]

    results = run(go())
    assert all(r.error is None for r in results)
    assert issued == ["tok-1"]
    token_req = rec.requests[0]
    assert b"grant_type=client_credentials" in token_req.content and b"scope=chat" in token_req.content
    assert rec.requests[1].headers["authorization"] == "Bearer tok-1"


def test_oauth_refreshes_before_expiry():
    clock = FakeClock()
    handler, issued = _oauth_handler(expires_in=100, tokens=["tok-1", "tok-2"])
    rec = Recorder(handler)
    adapter = make_adapter(make_config(auth=OAUTH), rec.transport, clock=clock)

    async def go():
        await adapter.send("a")
        clock.now += 80  # inside the 30s skew of a 100s token
        return await adapter.send("b")

    res = run(go())
    assert res.error is None and issued == ["tok-1", "tok-2"]
    assert rec.requests[-1].headers["authorization"] == "Bearer tok-2"


def test_oauth_refreshes_once_on_401():
    state = {"valid": "tok-1"}

    def handler(req, n):
        if req.url.path == "/token":
            tok = f"tok-{sum(1 for r in rec.requests if r.url.path == '/token')}"
            return httpx.Response(200, json={"access_token": tok, "expires_in": 3600})
        if req.headers.get("authorization") == f"Bearer {state['valid']}":
            return httpx.Response(200, json=OK)
        return httpx.Response(401, json={})

    rec = Recorder(handler)
    adapter = make_adapter(make_config(auth=OAUTH), rec.transport)

    async def go():
        await adapter.send("a")
        state["valid"] = "tok-2"  # server revokes tok-1
        return await adapter.send("b")

    res = run(go())
    assert res.error is None and res.attempts == 2
    assert sum(1 for r in rec.requests if r.url.path == "/token") == 2


def test_oauth_persistent_401_stops_after_one_refresh():
    def handler(req, n):
        if req.url.path == "/token":
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        return httpx.Response(401, json={})

    rec = Recorder(handler)
    res = run(make_adapter(make_config(auth=OAUTH), rec.transport).send("q"))
    assert res.error and res.error.kind is TargetErrorKind.HTTP_4XX
    assert [r.url.path for r in rec.requests].count("/chat") == 2


def test_oauth_token_failure_is_typed_and_leaks_nothing(caplog):
    rec = Recorder(lambda r, n: httpx.Response(400, json={"echo": "csecret"}))
    with caplog.at_level(logging.DEBUG):
        res = run(make_adapter(make_config(auth=OAUTH), rec.transport).send("q"))
    assert res.error and res.error.kind is TargetErrorKind.HTTP_4XX
    assert [r.url.path for r in rec.requests] == ["/token"]
    assert "csecret" not in caplog.text and "csecret" not in str(res.error)


LOGIN = {
    "type": "cookie_login",
    "login_url": "http://fake-target.test/login",
    "username": "bot",
    "password": "pw-secret",
}


def test_cookie_login_then_reuses_cookie():
    def handler(req, n):
        if req.url.path == "/login":
            return httpx.Response(200, json={}, headers={"set-cookie": "auth=abc; Path=/"})
        if "auth=abc" not in req.headers.get("cookie", ""):
            return httpx.Response(401, json={})
        return httpx.Response(200, json=OK)

    rec = Recorder(handler)
    adapter = make_adapter(make_config(auth=LOGIN), rec.transport)

    async def go():
        return [await adapter.send("a"), await adapter.send("b")]

    results = run(go())
    assert all(r.error is None for r in results)
    assert [r.url.path for r in rec.requests] == ["/login", "/chat", "/chat"]
    assert b'"username":"bot"' in rec.requests[0].content.replace(b" ", b"")


def test_cookie_login_failure_typed(caplog):
    rec = Recorder(lambda r, n: httpx.Response(403, json={}))
    with caplog.at_level(logging.DEBUG):
        res = run(make_adapter(make_config(auth=LOGIN), rec.transport).send("q"))
    assert res.error and res.error.kind is TargetErrorKind.HTTP_4XX
    assert "pw-secret" not in caplog.text and "pw-secret" not in str(res.error)
