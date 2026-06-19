"""Tests for the LLM abstraction, factory, structured outputs, and observability logging."""

import tempfile
from pathlib import Path

from cyberredteam.llm.factory import get_llm_for_agent, load_prompt, get_deployment_for_agent
from cyberredteam.llm.schemas import (
    AttackCase,
    AttackPlan,
    DefensePatch,
    EvaluationResult,
    SecurityReport,
)
from cyberredteam.storage.artifact_store import SQLiteStore
from cyberredteam.storage.models import LLMCallRecord


def test_factory_and_fake_llm():
    """Test that the LLM factory returns an ObservableLLM wrapped mock client when no credentials are present."""
    # Ensure it returns our fake implementation
    llm = get_llm_for_agent("strategist")
    assert llm is not None
    assert llm.agent_name == "strategist"
    assert llm.deployment == get_deployment_for_agent("strategist")

    # Test load prompt
    prompt = load_prompt("strategist")
    assert "Strategist Agent" in prompt or "Role" in prompt


def test_structured_output_generation():
    """Test that the fake LLM correctly returns valid mock structured outputs for each schema."""
    llm = get_llm_for_agent("attacker")

    # Test AttackPlan structured invoke
    plan = llm.invoke_structured("system", "user", AttackPlan)
    assert isinstance(plan, AttackPlan)
    assert len(plan.strategies) > 0
    assert plan.rationale != ""

    # Test AttackCase structured invoke
    case = llm.invoke_structured("system", "user", AttackCase)
    assert isinstance(case, AttackCase)
    assert case.attack_type != ""
    assert case.generated_test_case != ""

    # Test EvaluationResult structured invoke
    evaluation = llm.invoke_structured("system", "user", EvaluationResult)
    assert isinstance(evaluation, EvaluationResult)
    assert evaluation.success is False
    assert evaluation.vulnerability_type != ""

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
