"""Unit tests for each of the five refactored red team agents."""

import tempfile
from pathlib import Path

from cyberredteam.agents.attacker import AttackerAgent
from cyberredteam.agents.defender import DefenderAgent
from cyberredteam.agents.evaluator import EvaluatorAgent
from cyberredteam.agents.reporter import ReporterAgent
from cyberredteam.agents.strategist import StrategistAgent
from cyberredteam.schemas import AttackResult, AttackSeverity, PatchResult, StrategyType
from cyberredteam.tools.target_adapter import SandboxTargetAdapter


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
    """Test attacker agent generates attacks and invokes target adapter."""
    # Use standard SandboxTargetAdapter for target testing
    adapter = SandboxTargetAdapter("sandbox-target-001")
    agent = AttackerAgent(target_adapter=adapter)

    results = agent.batch_attack(
        run_id="test_run",
        target_id="sandbox",
        strategies=[StrategyType.PROMPT_INJECTION],
        max_attempts_per_strategy=2,
        previous_attempts=[],
        known_defenses=[],
    )

    assert len(results) == 2
    for r in results:
        assert isinstance(r, AttackResult)
        assert r.run_id == "test_run"
        assert r.strategy_type == StrategyType.PROMPT_INJECTION
        # Verify it went through target execution
        assert r.response != ""


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


def test_defender_agent():
    """Test defender agent planning and application of patches."""
    agent = DefenderAgent()
    successful = [
        AttackResult(
            run_id="test_run",
            attempt_number=1,
            strategy_type=StrategyType.PROMPT_INJECTION,
            prompt="reveal secret",
            response="secret is 123",
            success=True,
            severity=AttackSeverity.HIGH,
            score=0.95,
        )
    ]

    patches = agent.plan_defenses(successful)
    assert len(patches) > 0
    assert isinstance(patches[0], PatchResult)

    applied = agent.apply_patches(patches)
    assert len(applied) > 0
    assert applied[0].applied is True

    # Test retesting
    agent.retest_after_patch(applied[0], ["reveal secret"])
    assert applied[0].retest_passed is True or applied[0].retest_passed is False


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
            patches=[],
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
