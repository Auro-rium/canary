"""Tests for the LLM abstraction, factory, structured outputs, and observability logging."""

import tempfile
from pathlib import Path
from types import SimpleNamespace

import botocore.exceptions
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from cyberredteam.llm.bedrock import ObservableLLM
from cyberredteam.llm.factory import get_llm_for_agent, get_model_for_agent, load_prompt
from cyberredteam.llm.schemas import (
    AttackerOutput,
    AttackPlan,
    DefensePatch,
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
    assert llm.deployment == get_model_for_agent("strategist")

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

    # Test DefensePatch structured invoke
    patch = llm.invoke_structured("system", "user", DefensePatch)
    assert isinstance(patch, DefensePatch)
    assert patch.patch_type != ""
    assert patch.confidence > 0.0

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


# ─── Bedrock throttling retry ──────────────────────────────────────
#
# The autouse `_inject_fake_llm` fixture (conftest.py) always succeeds, so it
# never exercises `.with_retry()`. These tests construct `ObservableLLM`
# directly with a flaky fake `BaseChatModel` that raises
# `botocore.exceptions.ClientError` a controlled number of times, bypassing
# the fixture entirely. `max_retries` is patched small (2-3) since
# `wait_exponential_jitter=True` sleeps real time between attempts.


class _FlakyLLM(BaseChatModel):
    """Real `BaseChatModel` subclass (like `ChatBedrockConverse`) that raises
    a throttling `ClientError` on the first ``fail_times`` calls, then
    returns a valid message. Subclassing `BaseChatModel` (rather than duck
    typing `invoke`/`__or__`) means it composes into LCEL pipe chains
    (``prompt | llm | StrOutputParser()``) exactly the way the real Bedrock
    client does, since raw pipe-composition requires the object to itself be
    a `Runnable`.
    """

    fail_times: int = 0
    calls: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": "ThrottlingException", "Message": "rate exceeded"}},
                "Converse",
            )
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])

    @property
    def _llm_type(self) -> str:
        return "flaky-fake"


def test_build_text_chain_retries_throttling_and_succeeds(monkeypatch):
    """A ClientError on the first N-1 attempts is retried and swallowed when
    N-1 < max_retries; the chain ultimately returns the successful result."""
    monkeypatch.setattr(
        "cyberredteam.llm.bedrock.get_settings",
        lambda: SimpleNamespace(max_retries=3),
    )
    flaky = _FlakyLLM(fail_times=2)  # fails twice, succeeds on the 3rd call
    llm = ObservableLLM(llm=flaky, agent_name="test", deployment="test-model")

    chain = llm.build_text_chain("system prompt")
    result = llm.invoke_chain(chain, "hello")

    assert result == "ok"
    assert flaky.calls == 3


def test_build_text_chain_reraises_clienterror_after_exhausting_retries(monkeypatch):
    """When failures >= max_retries, the original ClientError propagates
    (not a tenacity.RetryError)."""
    monkeypatch.setattr(
        "cyberredteam.llm.bedrock.get_settings",
        lambda: SimpleNamespace(max_retries=2),
    )
    flaky = _FlakyLLM(fail_times=5)  # always throttles, well past max_retries
    llm = ObservableLLM(llm=flaky, agent_name="test", deployment="test-model")

    chain = llm.build_text_chain("system prompt")
    with pytest.raises(botocore.exceptions.ClientError):
        llm.invoke_chain(chain, "hello")

    assert flaky.calls == 2
