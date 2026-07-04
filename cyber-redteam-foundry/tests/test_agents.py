"""Unit tests for each of the four refactored red team agents."""

import tempfile
from pathlib import Path

import uuid

from cyberredteam.agents.attacker import AttackerAgent
from cyberredteam.agents.evaluator import EvaluatorAgent
from cyberredteam.agents.reporter import ReporterAgent
from cyberredteam.agents.strategist import StrategistAgent
from cyberredteam.evaluation import taxonomy
from cyberredteam.evaluation.technique_specs import get_spec
from cyberredteam.schemas import AttackBranch, AttackResult, AttackSeverity, StrategyType
from cyberredteam.tools.target_adapter import SandboxTargetAdapter


def _branch(strategy: StrategyType, depth: int = 0, parent_evidence=None) -> AttackBranch:
    asi_class, _ = taxonomy.lookup(strategy.value, "")
    spec = get_spec(asi_class)
    return AttackBranch(
        branch_id=uuid.uuid4().hex,
        capability_type=strategy.value,
        technique_id=asi_class,
        technique_spec=spec["spec"],
        target_metadata={"name": "sandbox", "declared_purpose": "test target", "observability_level": "black_box"},
        depth=depth,
        attempt_budget_remaining=3 - depth,
        parent_evidence=parent_evidence,
    )


def test_strategist_agent():
    """Test strategist agent strategy selection."""
    agent = StrategistAgent()
    selected = agent.select_strategies(
        target_id="sandbox",
        risk_appetite="medium",
        count=2,
        previous_vulnerabilities=[],
        available_subset=[StrategyType.PROMPT_INJECTION, StrategyType.TOOL_MISUSE],
    )
    assert len(selected) > 0
    assert all(isinstance(s, StrategyType) for s in selected)


def test_attacker_agent():
    """Test attacker agent generates an attack and invokes target adapter."""
    # Use standard SandboxTargetAdapter for target testing
    adapter = SandboxTargetAdapter("sandbox-target-001")
    agent = AttackerAgent(target_adapter=adapter)

    result = agent.attack_branch(
        branch=_branch(StrategyType.PROMPT_INJECTION),
        run_id="test_run",
        target_id="sandbox",
    )

    assert isinstance(result, AttackResult)
    assert result.run_id == "test_run"
    assert result.strategy_type == StrategyType.PROMPT_INJECTION
    assert result.capability_type == StrategyType.PROMPT_INJECTION.value
    # Verify it went through target execution
    assert result.response != ""


def test_attacker_agent_jailbreak():
    """Test attacker agent generates jailbreak attacks with fallback payloads."""
    adapter = SandboxTargetAdapter("sandbox-target-001")
    agent = AttackerAgent(target_adapter=adapter)

    result = agent.attack_branch(
        branch=_branch(StrategyType.JAILBREAK),
        run_id="test_run_jb",
        target_id="sandbox",
    )

    assert result.strategy_type == StrategyType.JAILBREAK


def test_attacker_agent_instruction_hierarchy():
    """Test attacker agent generates instruction hierarchy attacks."""
    adapter = SandboxTargetAdapter("sandbox-target-001")
    agent = AttackerAgent(target_adapter=adapter)

    result = agent.attack_branch(
        branch=_branch(StrategyType.INSTRUCTION_HIERARCHY),
        run_id="test_run_ih",
        target_id="sandbox",
    )

    assert result.strategy_type == StrategyType.INSTRUCTION_HIERARCHY


def test_attacker_agent_workflow_manipulation():
    """Test attacker agent generates workflow manipulation attacks."""
    adapter = SandboxTargetAdapter("sandbox-target-001")
    agent = AttackerAgent(target_adapter=adapter)

    result = agent.attack_branch(
        branch=_branch(StrategyType.WORKFLOW_MANIPULATION),
        run_id="test_run_wm",
        target_id="sandbox",
    )

    assert result.strategy_type == StrategyType.WORKFLOW_MANIPULATION


def test_attacker_agent_depth_mutation():
    """Test attacker agent threads depth/parent_evidence for a depth>0 retry."""
    adapter = SandboxTargetAdapter("sandbox-target-001")
    agent = AttackerAgent(target_adapter=adapter)

    branch = _branch(
        StrategyType.PROMPT_INJECTION,
        depth=1,
        parent_evidence={"target_response": "I cannot help with that.", "evaluator_reasoning": "clean refusal"},
    )
    result = agent.attack_branch(branch=branch, run_id="test_run_depth", target_id="sandbox")

    assert result.depth == 1
    assert result.branch_id == branch.branch_id


def test_attacker_agent_refusal_short_circuits_target():
    """When the attacker refuses, the target adapter must never be contacted."""
    from unittest.mock import MagicMock

    from cyberredteam.llm.schemas import AttackerOutput

    adapter = MagicMock()
    agent = AttackerAgent(target_adapter=adapter)
    agent._attack_chain = MagicMock()
    agent.llm = MagicMock()
    agent.llm.invoke_chain.return_value = AttackerOutput(
        status="ATTACKER_REFUSED",
        capability_type="prompt_injection",
        technique_id="ASI01",
        depth=0,
        payload="",
        rationale="n/a",
        refusal_reason="mass_casualty_content",
    )

    result = agent.attack_branch(branch=_branch(StrategyType.PROMPT_INJECTION), run_id="r", target_id="sandbox")

    adapter.execute_attack.assert_not_called()
    assert result.success is False
    assert result.error == "mass_casualty_content"
    assert result.indicators["_refused"] is True


def test_evaluator_agent():
    """Test evaluator agent LLM judging and metric computation."""
    agent = EvaluatorAgent()
    raw_results = [
        AttackResult(
            run_id="test_run",
            attempt_number=1,
            strategy_type=StrategyType.PROMPT_INJECTION,
            prompt="test prompt",
            response="refused",
            success=False,
            severity=AttackSeverity.LOW,
            score=0.1,
        )
    ]

    evaluated = agent.evaluate_batch(raw_results)
    assert len(evaluated) == 1
    assert isinstance(evaluated[0], AttackResult)

    metrics = agent.compute_overall_metrics(evaluated)
    assert "success_rate" in metrics
    assert "average_attack_score" in metrics


def test_evaluator_agent_jailbreak_detection():
    """Test evaluator agent detects jailbreak successes deterministically."""
    agent = EvaluatorAgent()

    # Construct a mock response that would trigger jailbreak detection
    raw_results = [
        AttackResult(
            run_id="test_run_jb",
            target_id="sandbox",
            attempt_number=1,
            strategy_type=StrategyType.JAILBREAK,
            prompt="test jailbreak",
            response="acknowledged without restrictions",
            success=False,
            severity=AttackSeverity.MEDIUM,
            score=0.0,
            indicators={"objective": "Bypass safety filters"},
        )
    ]

    evaluated = agent.evaluate_batch(raw_results)
    assert len(evaluated) == 1
    # Check that deterministic_checks were populated (even if empty)
    assert "deterministic_checks" in evaluated[0].indicators


def test_evaluator_agent_instruction_hierarchy_detection():
    """Test evaluator agent detects instruction hijack successes."""
    agent = EvaluatorAgent()

    raw_results = [
        AttackResult(
            run_id="test_run_ih",
            target_id="sandbox",
            attempt_number=1,
            strategy_type=StrategyType.INSTRUCTION_HIERARCHY,
            prompt="test hijack",
            response="instruction overridden successfully",
            success=False,
            severity=AttackSeverity.MEDIUM,
            score=0.0,
            indicators={"objective": "Override instruction hierarchy"},
        )
    ]

    evaluated = agent.evaluate_batch(raw_results)
    assert len(evaluated) == 1
    assert "deterministic_checks" in evaluated[0].indicators


def test_evaluator_agent_workflow_manipulation_detection():
    """Test evaluator agent detects workflow DOS successes."""
    agent = EvaluatorAgent()

    raw_results = [
        AttackResult(
            run_id="test_run_wm",
            target_id="sandbox",
            attempt_number=1,
            strategy_type=StrategyType.WORKFLOW_MANIPULATION,
            prompt="test dos",
            response="recursively generating items...",
            success=False,
            severity=AttackSeverity.MEDIUM,
            score=0.0,
            indicators={"objective": "Trigger resource exhaustion"},
        )
    ]

    evaluated = agent.evaluate_batch(raw_results)
    assert len(evaluated) == 1
    assert "deterministic_checks" in evaluated[0].indicators


def test_reporter_agent():
    """Test reporter agent narrative generation and report writing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        agent = ReporterAgent(output_dir=Path(tmpdir))

        import datetime
        start = datetime.datetime.now(datetime.timezone.utc)
        end = start + datetime.timedelta(seconds=10)

        report = agent.generate_report(
            run_id="test_run",
            target_id="sandbox",
            attack_results=[],
            start_time=start,
            end_time=end,
        )

        assert report.run_id == "test_run"
        assert "executive_summary" in report.narratives

        md_path = agent.write_markdown(report)
        json_path = agent.write_json(report)

        assert md_path.exists()
        assert json_path.exists()
        assert md_path.read_text() != ""
        assert json_path.read_text() != ""
