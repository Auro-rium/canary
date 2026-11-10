"""Backboard backend tests: httpx.MockTransport only, no network."""

import json
from types import SimpleNamespace

import httpx
import pytest
from pydantic import BaseModel

from cyberredteam.llm import factory
from cyberredteam.llm.backboard import (
    BackboardError,
    BackboardRetryableError,
    ChatBackboard,
    extract_json,
)
from cyberredteam.llm.observable import ObservableLLM


class Verdict(BaseModel):
    label: str
    score: float


def _reply(content, status=200, **extra):
    return httpx.Response(status, json={"content": content, "status": "COMPLETED", **extra})


class _Server:
    """Scripted Backboard: pops one response per request and records requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses.pop(0)

    def payload(self, i):
        return json.loads(self.requests[i].content)


def _llm(server, **kw):
    return ChatBackboard(
        api_key="k",
        provider="anthropic",
        model_name="claude-x",
        transport=httpx.MockTransport(server),
        **kw,
    )


def _observable(server, **kw):
    return ObservableLLM(llm=_llm(server, **kw), agent_name="t", deployment="anthropic/claude-x")


@pytest.fixture(autouse=True)
def _fast_retries(monkeypatch):
    monkeypatch.setattr(
        "cyberredteam.llm.observable.get_settings", lambda: SimpleNamespace(max_retries=3)
    )
    monkeypatch.setattr("tenacity.nap.time.sleep", lambda s: None)


def test_extract_json_handles_fences_and_prose():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! Here: {"a": 2} hope it helps') == {"a": 2}
    with pytest.raises(ValueError):
        extract_json("no json here")


def test_text_request_shape_and_headers():
    server = _Server(_reply("hello", input_tokens=3, output_tokens=2, total_tokens=5))
    llm = _observable(server, temperature=0.0)
    assert llm.invoke_text("be brief", "hi") == "hello"
    req = server.requests[0]
    assert req.url.path.endswith("/threads/messages")
    assert req.headers["X-API-Key"] == "k"
    body = server.payload(0)
    assert body["llm_provider"] == "anthropic"
    assert body["model_name"] == "claude-x"
    assert body["system_prompt"] == "be brief"
    assert body["content"] == "hi"
    assert "thread_id" not in body
    assert "temperature" not in body  # undocumented by Backboard; not sent


def test_structured_success():
    server = _Server(
        _reply('{"label": "ok", "score": 0.5}', total_tokens=9, input_tokens=4, output_tokens=5)
    )
    result = _observable(server).invoke_structured("sys", "msg", Verdict)
    assert result == Verdict(label="ok", score=0.5)
    sys_prompt = server.payload(0)["system_prompt"]
    assert "JSON schema" in sys_prompt and "sys" in sys_prompt
    assert len(server.requests) == 1


def test_structured_json_in_code_fence():
    server = _Server(_reply('```json\n{"label": "ok", "score": 1}\n```'))
    assert _observable(server).invoke_structured("s", "m", Verdict).score == 1.0


def test_structured_repair_reask_then_success():
    server = _Server(_reply('{"label": "ok"}'), _reply('{"label": "ok", "score": 0.1}'))
    result = _observable(server).invoke_structured("s", "m", Verdict)
    assert result.score == 0.1
    assert len(server.requests) == 2
    repair = server.payload(1)["content"]
    assert "score" in repair and "invalid" in repair.lower()


def test_structured_fails_closed_after_one_repair():
    server = _Server(
        _reply("not json"), _reply('{"label": "ok"}'), _reply('{"label":"ok","score":1}')
    )
    with pytest.raises(ValueError):
        _observable(server).invoke_structured("s", "m", Verdict)
    assert len(server.requests) == 2  # exactly one repair, never a third call


def test_429_retried_then_success():
    server = _Server(httpx.Response(429), httpx.Response(503), _reply("done"))
    assert _observable(server).invoke_text("s", "m") == "done"
    assert len(server.requests) == 3


def test_429_exhausts_retries():
    server = _Server(*[httpx.Response(429)] * 3)
    with pytest.raises(BackboardRetryableError):
        _observable(server).invoke_text("s", "m")
    assert len(server.requests) == 3


def test_401_not_retried():
    server = _Server(httpx.Response(401, text="bad key"), _reply("never"))
    with pytest.raises(BackboardError) as exc:
        _observable(server).invoke_text("s", "m")
    assert not isinstance(exc.value, BackboardRetryableError)
    assert len(server.requests) == 1


def test_failed_run_is_non_retryable():
    server = _Server(httpx.Response(200, json={"status": "FAILED", "content": ""}))
    with pytest.raises(BackboardError):
        _observable(server).invoke_text("s", "m")
    assert len(server.requests) == 1


# ─── factory ───────────────────────────────────────────────────
# conftest patches ``factory.get_llm`` with a fake; restore the real one here.


@pytest.fixture
def real_get_llm(monkeypatch):
    import importlib

    real = importlib.import_module("cyberredteam.llm.factory")
    monkeypatch.setattr(real, "get_llm", _REAL_GET_LLM)
    return real


_REAL_GET_LLM = factory.get_llm


def test_factory_requires_api_key(real_get_llm, monkeypatch):
    monkeypatch.setenv("BACKBOARD_API_KEY", "")
    with pytest.raises(RuntimeError, match="BACKBOARD_API_KEY"):
        factory.get_llm("m", agent_name="attacker")


def test_judge_and_evaluator_temperature_forced_to_zero(real_get_llm, monkeypatch):
    monkeypatch.setenv("BACKBOARD_API_KEY", "k")
    for role in ("judge", "evaluator"):
        assert factory.get_role_config(role)["temperature"] == 0.0
        assert factory.get_llm_for_agent(role).llm.temperature == 0.0
    assert factory.get_llm("m", agent_name="judge", temperature=0.9).llm.temperature == 0.0


def test_env_overrides_per_role(real_get_llm, monkeypatch):
    monkeypatch.setenv("BACKBOARD_API_KEY", "k")
    monkeypatch.setenv("BACKBOARD_ATTACKER_PROVIDER", "google")
    monkeypatch.setenv("BACKBOARD_ATTACKER_MODEL_NAME", "gemini-x")
    llm = factory.get_llm_for_agent("attacker")
    assert (llm.llm.provider, llm.llm.model_name) == ("google", "gemini-x")
    assert llm.deployment == "google/gemini-x"


def test_all_roles_configured(monkeypatch):
    for role in factory.ROLES:
        monkeypatch.delenv(f"BACKBOARD_{role.upper()}_PROVIDER", raising=False)
        monkeypatch.delenv(f"BACKBOARD_{role.upper()}_MODEL_NAME", raising=False)
    # Values must come from configs/models.yaml, not the settings fallbacks.
    assert factory._load_models_config(), "configs/models.yaml was not loaded"
    for role in ("evaluator", "judge"):
        cfg = factory.get_role_config(role)
        assert (cfg["provider"], cfg["model_name"]) == ("anthropic", "claude-sonnet-5-5")
        assert cfg["temperature"] == 0.0
    for role in ("planner", "strategist", "attacker", "reporter"):
        cfg = factory.get_role_config(role)
        assert (cfg["provider"], cfg["model_name"]) == ("openai", "gpt-4o")
        assert cfg["temperature"] is not None


def test_api_key_never_leaks():
    llm = ChatBackboard(api_key="sk-super-secret", transport=httpx.MockTransport(_Server()))
    for text in (repr(llm), str(llm), str(llm.model_dump()), llm.model_dump_json()):
        assert "sk-super-secret" not in text


def test_api_key_sent_in_header():
    server = _Server(_reply("x"))
    ChatBackboard(
        api_key="sk-header", transport=httpx.MockTransport(server)
    ).invoke("hi")
    assert server.requests[0].headers["X-API-Key"] == "sk-header"


def test_non_json_200_body_is_backboard_error():
    server = _Server(httpx.Response(200, text="<html>oops</html>"))
    with pytest.raises(BackboardError, match="non-JSON"):
        _observable(server).invoke_text("s", "m")


def test_error_message_does_not_echo_raw_body():
    secret_body = "x" * 500 + "SENSITIVE"
    server = _Server(httpx.Response(400, text=secret_body))
    with pytest.raises(BackboardError) as exc:
        _observable(server).invoke_text("s", "m")
    assert "SENSITIVE" not in str(exc.value)
    server = _Server(httpx.Response(400, json={"error": {"code": "bad_model"}}))
    with pytest.raises(BackboardError, match="bad_model"):
        _observable(server).invoke_text("s", "m")


def test_transport_error_retried_then_success():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("boom", request=request)
        return _reply("recovered")

    assert _observable(handler).invoke_text("s", "m") == "recovered"
    assert calls["n"] == 2


def test_empty_body_retried_then_success():
    server = _Server(_reply(""), _reply("filled"))
    assert _observable(server).invoke_text("s", "m") == "filled"
    assert len(server.requests) == 2


def test_merge_usage_sums_or_keeps_available_side():
    from langchain_core.messages import AIMessage

    from cyberredteam.llm.backboard import _merge_usage

    u = {"input_tokens": 1, "output_tokens": 2, "total_tokens": 3}
    both = _merge_usage(AIMessage(content="a", usage_metadata=u), AIMessage(content="b", usage_metadata=u))
    assert both.usage_metadata["total_tokens"] == 6
    only_first = _merge_usage(AIMessage(content="a", usage_metadata=u), AIMessage(content="b"))
    assert only_first.usage_metadata == u
