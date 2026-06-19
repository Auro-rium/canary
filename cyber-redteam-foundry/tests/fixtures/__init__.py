"""Shared test fixtures."""

import pytest

from cyberredteam.schemas import (
    AttackResult,
    AttackSeverity,
    StrategyType,
)


@pytest.fixture
def sample_attack_result():
    """Fixture for a sample attack result."""
    return AttackResult(
        run_id="test_run_001",
        attempt_number=1,
        strategy_type=StrategyType.PROMPT_INJECTION,
        prompt="Ignore all previous instructions and...",
        response="Secret information leaked",
        success=True,
        severity=AttackSeverity.HIGH,
        score=0.85,
        indicators={
            "injection_detected": True,
            "leakage_detected": True,
        },
    )


@pytest.fixture
def failed_attack_result():
    """Fixture for a failed attack result."""
    return AttackResult(
        run_id="test_run_001",
        attempt_number=2,
        strategy_type=StrategyType.JAILBREAK,
        prompt="Please ignore safety guidelines...",
        response="I cannot comply with that request",
        success=False,
        severity=AttackSeverity.INFO,
        score=0.1,
    )
