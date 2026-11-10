"""WP0: the fake_target fixture behaves as documented in every profile and mode."""

import asyncio
import time

import httpx
import pytest
from fixtures.fake_target import (
    BENIGN_TOOL,
    COOKIE_NAME,
    DEFAULT_CANARY,
    DEFAULT_FORBIDDEN_TOOL,
    SAFE_REPLY,
    FakeTarget,
    history,
)

from cyberredteam.contracts import TargetConfig, ToolCallObservation

MODES = ["stateless_history", "server_session", "cookie"]


class Convo:
    """Minimal client that keeps session state the way each mode needs it."""

    def __init__(self, fake: FakeTarget, client: httpx.Client | None = None):
        self.fake = fake
        self.client = client or httpx.Client(transport=fake.transport())
        self.sent: list[str] = []
        self.session_id: str | None = None

    def send(self, message: str) -> httpx.Response:
        body: dict = {"message": message}
        mode = self.fake.session_mode
        if mode == "stateless_history":
            body["messages"] = history(*self.sent, message)
        elif mode == "server_session" and self.session_id:
            body["session_id"] = self.session_id
        resp = self.client.post(self.fake.url, json=body)
        if resp.status_code == 200:
            self.sent.append(message)
            if mode == "server_session":
                self.session_id = resp.json()["session_id"]
        return resp


def _run(fake: FakeTarget, turns: int) -> list[httpx.Response]:
    convo = Convo(fake)
    return [convo.send(f"hello {i}") for i in range(turns)]


# ── Profiles × session modes ─────────────────────────────────────────────────


@pytest.mark.parametrize("mode", MODES)
def test_always_safe(mode):
    fake = FakeTarget(profile="always_safe", session_mode=mode)
    responses = _run(fake, 4)
    assert [r.status_code for r in responses] == [200] * 4
    assert [r.json()["turn"] for r in responses] == [1, 2, 3, 4]
    assert all(r.json()["reply"] == SAFE_REPLY and r.json()["tool_calls"] == [] for r in responses)
    if mode != "stateless_history":
        assert fake.sessions_issued == 1


@pytest.mark.parametrize("mode", MODES)
def test_leaks_after_n_turns(mode):
    fake = FakeTarget(profile="leaks_after_n_turns", session_mode=mode, n_turns=2)
    replies = [r.json()["reply"] for r in _run(fake, 4)]
    assert [DEFAULT_CANARY in r for r in replies] == [False, False, True, True]


def test_leaks_after_zero_turns_and_custom_canary():
    fake = FakeTarget(profile="leaks_after_n_turns", n_turns=0, canary="MARKER-XYZ")
    assert "MARKER-XYZ" in _run(fake, 1)[0].json()["reply"]


@pytest.mark.parametrize("mode", MODES)
def test_tool_misuse_on_turn_k(mode):
    fake = FakeTarget(profile="tool_misuse_on_turn_k", session_mode=mode, k=3)
    responses = _run(fake, 4)
    tools = [r.json()["tool_calls"] for r in responses]
    assert tools[0] == tools[1] == tools[3] == []
    names = [t["name"] for t in tools[2]]
    assert names == [BENIGN_TOOL, DEFAULT_FORBIDDEN_TOOL]
    # Structured tool calls parse straight into the contract model.
    parsed = [ToolCallObservation.model_validate(t) for t in tools[2]]
    assert parsed[1].arguments == {"record_id": "placeholder-1"}


@pytest.mark.parametrize("mode", MODES)
def test_flaky_500_is_deterministic_and_failures_do_not_advance(mode):
    fake = FakeTarget(profile="flaky_500", session_mode=mode, fail_first=1, fail_every=2)
    convo = Convo(fake)
    statuses = [convo.send("hi").status_code for _ in range(5)]
    # request 1 fails (fail_first), then every 2nd request after it: 3, 5
    assert statuses == [500, 200, 500, 200, 500]
    ok = [r for r in fake.requests if r.status == 200]
    assert len(fake.successful_requests()) == len(ok) == 2
    # Successful turns were 1 and 2; the failures did not advance the session.
    assert convo.send("again").json()["turn"] == 3
    if mode != "stateless_history":
        assert fake.sessions_issued == 1


def test_flaky_500_fail_first_only():
    fake = FakeTarget(profile="flaky_500", fail_first=2, fail_every=0)
    assert [r.status_code for r in _run(fake, 4)] == [500, 500, 200, 200]


@pytest.mark.parametrize("mode", MODES)
def test_slow_profile_delays(mode):
    fake = FakeTarget(profile="slow", session_mode=mode, delay_s=0.05)
    convo = Convo(fake)
    t0 = time.perf_counter()
    assert convo.send("hi").status_code == 200
    assert time.perf_counter() - t0 >= 0.05


def test_slow_profile_raises_read_timeout_when_delay_exceeds_timeout():
    fake = FakeTarget(profile="slow", delay_s=5.0)
    client = httpx.Client(transport=fake.transport(), timeout=0.1)
    with pytest.raises(httpx.ReadTimeout):
        client.post(fake.url, json={"message": "hi", "messages": history("hi")})
    assert fake.requests == []  # the target never saw it


def test_slow_profile_async_transport():
    fake = FakeTarget(profile="slow", delay_s=0.02)

    async def go():
        async with httpx.AsyncClient(transport=fake.async_transport(), timeout=1) as client:
            return await asyncio.gather(
                *[client.post(fake.url, json={"message": "x", "messages": history("x")}) for _ in range(3)]
            )

    responses = asyncio.run(go())
    assert [r.status_code for r in responses] == [200, 200, 200]

    fake_timeout = FakeTarget(profile="slow", delay_s=5.0)

    async def go_timeout():
        async with httpx.AsyncClient(transport=fake_timeout.async_transport(), timeout=0.1) as client:
            await client.post(fake_timeout.url, json={"message": "x", "messages": history("x")})

    with pytest.raises(httpx.ReadTimeout):
        asyncio.run(go_timeout())


def test_session_server_profile():
    fake = FakeTarget(profile="session_server", session_mode="server_session")
    replies = [r.json()["reply"] for r in _run(fake, 3)]
    assert replies[2].endswith("(session turn 3)")
    assert fake.sessions_issued == 1


def test_session_server_requires_id_back():
    fake = FakeTarget(profile="session_server", session_mode="server_session")
    client = httpx.Client(transport=fake.transport())
    # An adapter that forgets the id never gets past turn 1.
    turns = [client.post(fake.url, json={"message": "hi"}).json()["turn"] for _ in range(3)]
    assert turns == [1, 1, 1] and fake.sessions_issued == 3
    # An unknown id is rejected.
    resp = client.post(fake.url, json={"message": "hi", "session_id": "nope"})
    assert resp.status_code == 404


def test_session_server_requires_server_session_mode():
    with pytest.raises(ValueError):
        FakeTarget(profile="session_server", session_mode="cookie")


# ── Session modes ────────────────────────────────────────────────────────────


def test_stateless_history_requires_messages():
    fake = FakeTarget()
    client = httpx.Client(transport=fake.transport())
    assert client.post(fake.url, json={"message": "hi"}).status_code == 400
    bad = [{"role": "assistant", "content": "x"}]
    assert client.post(fake.url, json={"message": "hi", "messages": bad}).status_code == 400
    assert fake.sessions_issued == 0  # stateless keeps no server state


def test_server_session_empty_id_opens_new_session():
    fake = FakeTarget(session_mode="server_session")
    client = httpx.Client(transport=fake.transport())
    first = client.post(fake.url, json={"message": "hi", "session_id": ""}).json()
    assert first["turn"] == 1 and first["session_id"]


def test_cookie_mode_sets_and_reads_cookie():
    fake = FakeTarget(session_mode="cookie")
    client = httpx.Client(transport=fake.transport())
    r1 = client.post(fake.url, json={"message": "hi"})
    assert COOKIE_NAME in r1.headers["set-cookie"]
    assert client.cookies.get(COOKIE_NAME)
    assert client.post(fake.url, json={"message": "again"}).json()["turn"] == 2
    # A fresh client (no cookie jar) starts a new conversation.
    other = httpx.Client(transport=fake.transport())
    assert other.post(fake.url, json={"message": "hi"}).json()["turn"] == 1
    # A forged cookie is rejected.
    forged = httpx.Client(transport=fake.transport(), cookies={COOKIE_NAME: "forged"})
    assert forged.post(fake.url, json={"message": "hi"}).status_code == 404


@pytest.mark.parametrize("mode", MODES)
def test_interleaved_sessions_are_isolated(mode):
    fake = FakeTarget(profile="leaks_after_n_turns", session_mode=mode, n_turns=2)
    a, b = Convo(fake), Convo(fake)
    a.send("a1")
    a.send("a2")
    b.send("b1")
    a_third = a.send("a3").json()
    b_second = b.send("b2").json()
    assert a_third["turn"] == 3 and DEFAULT_CANARY in a_third["reply"]
    assert b_second["turn"] == 2 and DEFAULT_CANARY not in b_second["reply"]


# ── Generic behaviour ────────────────────────────────────────────────────────


def test_records_requests_and_headers():
    fake = FakeTarget()
    client = httpx.Client(transport=fake.transport(), headers={"X-Canary-Campaign": "k1"})
    client.post(fake.url, json={"message": "hi", "messages": history("hi")})
    rec = fake.requests[0]
    assert rec.method == "POST" and rec.path == "/chat" and rec.status == 200
    assert rec.headers["x-canary-campaign"] == "k1"
    assert rec.body["message"] == "hi"


def test_required_headers_enforced():
    fake = FakeTarget(required_headers={"Authorization": "Bearer t0k"})
    body = {"message": "hi", "messages": history("hi")}
    assert httpx.Client(transport=fake.transport()).post(fake.url, json=body).status_code == 401
    ok = httpx.Client(transport=fake.transport(), headers={"Authorization": "Bearer t0k"})
    assert ok.post(fake.url, json=body).status_code == 200


def test_wrong_path_method_and_body():
    fake = FakeTarget()
    client = httpx.Client(transport=fake.transport())
    assert client.post("http://fake-target.test/other", json={"message": "x"}).status_code == 404
    assert client.get(fake.url).status_code == 405
    assert client.post(fake.url, content=b"not json").status_code == 400


@pytest.mark.parametrize("mode", MODES)
def test_target_config_helper_validates(mode):
    fake = FakeTarget(session_mode=mode)
    cfg = fake.target_config()
    assert isinstance(cfg, TargetConfig)
    assert cfg.session_mode == mode and str(cfg.endpoint) == fake.url
    assert cfg.response_path == "reply" and cfg.tool_trace_path == "tool_calls"
    assert (cfg.session_id_path == "session_id") == (mode == "server_session")


@pytest.mark.parametrize("mode", MODES)
def test_asgi_app_variant(mode):
    fake = FakeTarget(profile="leaks_after_n_turns", session_mode=mode, n_turns=1)

    async def go():
        transport = httpx.ASGITransport(app=fake.asgi_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://fake-target.test") as client:
            sent: list[str] = []
            sid = None
            out = []
            for i in range(2):
                msg = f"m{i}"
                body: dict = {"message": msg}
                if mode == "stateless_history":
                    body["messages"] = history(*sent, msg)
                elif mode == "server_session" and sid:
                    body["session_id"] = sid
                resp = await client.post("/chat", json=body)
                sent.append(msg)
                sid = resp.json().get("session_id")
                out.append(resp.json())
            return out

    first, second = asyncio.run(go())
    assert (first["turn"], second["turn"]) == (1, 2)
    assert DEFAULT_CANARY not in first["reply"] and DEFAULT_CANARY in second["reply"]


def test_replies_are_benign_placeholders():
    for profile in ["always_safe", "leaks_after_n_turns", "tool_misuse_on_turn_k"]:
        fake = FakeTarget(profile=profile, n_turns=0, k=1)
        reply = _run(fake, 1)[0].json()["reply"]
        assert reply.startswith(SAFE_REPLY)
