"""Tests for the LLM abstraction, factory, structured outputs, and observability logging."""

import tempfile
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from cyberredteam.llm.backboard import BackboardRetryableError, ChatBackboard, extract_json
from cyberredteam.llm.observable import ObservableLLM
from cyberredteam.llm.factory import get_llm_for_agent, load_prompt
from cyberredteam.llm.schemas import (
    AttackerOutput,
    AttackPlan,
    EvaluationResult,
    SecurityReport,
)
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import LLMCallRecord


def test_factory_returns_observable_llm():
    """The factory returns an ObservableLLM tagged with the agent + model.

    (The underlying client is the injected FakeStructuredLLM — see conftest.)
    """
    llm = get_llm_for_agent("strategist")
    assert llm is not None
    assert llm.agent_name == "strategist"
    assert llm.deployment == "test-model"

    # Test load prompt
    prompt = load_prompt("strategist")
    assert "strategist" in prompt.lower() or "role" in prompt.lower()


def test_structured_output_generation():
    """The structured-output path returns valid instances for each schema."""
    llm = get_llm_for_agent("attacker")

    # Test AttackPlan structured invoke
    plan = llm.invoke_structured("system", "user", AttackPlan)
    assert isinstance(plan, AttackPlan)
    assert len(plan.categories) > 0
    assert plan.rationale != ""

    # Test AttackerOutput structured invoke
    output = llm.invoke_structured("system", "user", AttackerOutput)
    assert isinstance(output, AttackerOutput)
    assert output.status in ("OK", "ATTACKER_REFUSED")
    assert output.payload != ""

    # Test EvaluationResult structured invoke
    evaluation = llm.invoke_structured("system", "user", EvaluationResult)
    assert isinstance(evaluation, EvaluationResult)
    assert evaluation.boundary_failure is False or evaluation.boundary_failure is True
    assert evaluation.finding != ""

    # Test SecurityReport structured invoke
    report = llm.invoke_structured("system", "user", SecurityReport)
    assert isinstance(report, SecurityReport)
    assert report.executive_summary != ""
    assert report.attack_campaign != ""


def test_observability_logging_to_db():
    """Test that LLM calls are logged to the SQLite database via SQLiteStore."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_observability.db"
        store = SQLiteStore(db_path)

        # Call save_llm_call directly
        store.save_llm_call(
            agent_name="attacker",
            deployment="gpt-4o-mini",
            latency=1.23,
            input_hash="abc123input",
            output_hash="xyz789output",
            prompt_tokens=150,
            completion_tokens=50,
        )

        # Query the database directly to verify
        with store.SessionLocal() as session:
            records = session.query(LLMCallRecord).all()
            assert len(records) == 1
            record = records[0]
            assert record.agent_name == "attacker"
            assert record.deployment == "gpt-4o-mini"
            assert record.latency == 1.23
            assert record.input_hash == "abc123input"
            assert record.output_hash == "xyz789output"
            assert record.prompt_tokens == 150
            assert record.completion_tokens == 50


# ─── Provider throttling retry ──────────────────────────────────────
#
# The autouse `_inject_fake_llm` fixture (conftest.py) always succeeds, so it
# never exercises `.with_retry()`. These tests construct `ObservableLLM`
# directly with a flaky fake `BaseChatModel` that raises
# `BackboardRetryableError` a controlled number of times, bypassing
# the fixture entirely. `max_retries` is patched small (2-3) since
# `wait_exponential_jitter=True` sleeps real time between attempts.


class _FlakyLLM(BaseChatModel):
    """Real `BaseChatModel` subclass (like `ChatBackboard`) that raises
    a throttling error on the first ``fail_times`` calls, then
    returns a valid message. Subclassing `BaseChatModel` (rather than duck
    typing `invoke`/`__or__`) means it composes into LCEL pipe chains
    (``prompt | llm | StrOutputParser()``) exactly the way the real Backboard
    client does, since raw pipe-composition requires the object to itself be
    a `Runnable`.
    """

    fail_times: int = 0
    calls: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise BackboardRetryableError("Backboard returned HTTP 429")
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])

    @property
    def _llm_type(self) -> str:
        return "flaky-fake"


def test_build_text_chain_retries_throttling_and_succeeds(monkeypatch):
    """A throttling error on the first N-1 attempts is retried and swallowed when
    N-1 < max_retries; the chain ultimately returns the successful result."""
    monkeypatch.setattr(
        "cyberredteam.llm.observable.get_settings",
        lambda: SimpleNamespace(max_retries=3),
    )
    flaky = _FlakyLLM(fail_times=2)  # fails twice, succeeds on the 3rd call
    llm = ObservableLLM(llm=flaky, agent_name="test", deployment="test-model")

    chain = llm.build_text_chain("system prompt")
    result = llm.invoke_chain(chain, "hello")

    assert result == "ok"
    assert flaky.calls == 3


def test_build_text_chain_reraises_error_after_exhausting_retries(monkeypatch):
    """When failures >= max_retries, the original error propagates
    (not a tenacity.RetryError)."""
    monkeypatch.setattr(
        "cyberredteam.llm.observable.get_settings",
        lambda: SimpleNamespace(max_retries=2),
    )
    flaky = _FlakyLLM(fail_times=5)  # always throttles, well past max_retries
    llm = ObservableLLM(llm=flaky, agent_name="test", deployment="test-model")

    chain = llm.build_text_chain("system prompt")
    with pytest.raises(BackboardRetryableError):
        llm.invoke_chain(chain, "hello")

    assert flaky.calls == 2


# ─── ChatBackboard transport ──────────────────────────────────────


def _backboard_response(monkeypatch, status_code=200, body=None):
    """Patch httpx.post to return a canned Backboard reply and capture the request."""
    captured = {}

    def _post(url, headers=None, json=None, timeout=None):
        captured.update(url=url, headers=headers, json=json)
        return httpx.Response(status_code, json=body or {}, request=httpx.Request("POST", url))

    monkeypatch.setattr("cyberredteam.llm.backboard.httpx.post", _post)
    return captured


def _client():
    return ChatBackboard(api_key="k", provider="anthropic", model_name="claude-test")


def test_backboard_sends_expected_request(monkeypatch):
    from langchain_core.messages import HumanMessage, SystemMessage

    captured = _backboard_response(monkeypatch, body={
        "content": "hello", "status": "COMPLETED",
        "input_tokens": 3, "output_tokens": 2, "total_tokens": 5,
    })
    message = _client().invoke([SystemMessage(content="be brief"), HumanMessage(content="hi")])

    assert captured["url"] == "https://app.backboard.io/api/threads/messages"
    assert captured["headers"]["X-API-Key"] == "k"
    assert captured["json"]["llm_provider"] == "anthropic"
    assert captured["json"]["model_name"] == "claude-test"
    assert captured["json"]["system_prompt"] == "be brief"
    assert captured["json"]["content"] == "hi"
    assert "thread_id" not in captured["json"]
    assert message.content == "hello"
    assert message.usage_metadata["total_tokens"] == 5


def test_backboard_structured_output_parses_fenced_json(monkeypatch):
    captured = _backboard_response(monkeypatch, body={
        "content": '```json\n{"categories": ["prompt_injection"], "priorities": ["high"], "rationale": "r"}\n```',
        "status": "COMPLETED", "total_tokens": 9, "input_tokens": 4, "output_tokens": 5,
    })
    from langchain_core.prompt_values import StringPromptValue

    chain = _client().with_structured_output(AttackPlan, include_raw=True)
    result = chain.invoke(StringPromptValue(text="plan"))
    assert isinstance(result["parsed"], AttackPlan)
    assert result["parsing_error"] is None
    assert result["raw"].usage_metadata["total_tokens"] == 9
    assert captured["json"]["json_output"] is True


def test_backboard_structured_output_reports_parse_failure(monkeypatch):
    _backboard_response(monkeypatch, body={"content": "not json", "status": "COMPLETED"})
    from langchain_core.prompt_values import StringPromptValue

    result = _client().with_structured_output(AttackPlan, include_raw=True).invoke(
        StringPromptValue(text="plan")
    )
    assert result["parsed"] is None
    assert result["parsing_error"] is not None


def test_backboard_error_classification(monkeypatch):
    from cyberredteam.llm.backboard import BackboardError

    _backboard_response(monkeypatch, status_code=503)
    with pytest.raises(BackboardRetryableError):
        _client().invoke("hi")

    _backboard_response(monkeypatch, status_code=401, body={"detail": "bad key"})
    with pytest.raises(BackboardError) as exc:
        _client().invoke("hi")
    assert not isinstance(exc.value, BackboardRetryableError)


def test_extract_json_finds_object_in_prose():
    assert extract_json('Sure! {"a": 1} hope that helps') == {"a": 1}


def test_factory_requires_backboard_key(monkeypatch):
    """With no key configured the real factory fails closed instead of faking output."""
    import importlib

    import cyberredteam.llm.factory as factory

    real = importlib.reload(factory)
    monkeypatch.setattr(
        "cyberredteam.settings.get_settings",
        lambda: SimpleNamespace(backboard_api_key=None),
    )
    with pytest.raises(RuntimeError, match="BACKBOARD_API_KEY"):
        real.get_llm("gpt-4o", agent_name="attacker")
