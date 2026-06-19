"""Tests for defense and patching."""


from cyberredteam.defense.patch_planner import PatchPlanner
from cyberredteam.schemas import AttackResult, AttackSeverity, PatchType, StrategyType


def test_patch_planner_initialization():
    """Test patch planner initializes."""
    planner = PatchPlanner()
    assert planner is not None


def test_patch_planner_generates_patches():
    """Test patch planner generates patches for attacks."""
    attack_result = AttackResult(
        run_id="test",
        attempt_number=1,
        strategy_type=StrategyType.PROMPT_INJECTION,
        prompt="test",
        response="test response",
        success=True,
        severity=AttackSeverity.HIGH,
        score=0.8,
    )

    patches = PatchPlanner.plan_patches([attack_result])
    assert len(patches) > 0
    assert patches[0].patch_type == PatchType.PROMPT_HARDENING


def test_patch_planner_handles_tool_attacks():
    """Test patches for tool misuse attacks."""
    attack_result = AttackResult(
        run_id="test",
        attempt_number=1,
        strategy_type=StrategyType.TOOL_MISUSE,
        prompt="test",
        response="executed dangerous command",
        success=True,
        severity=AttackSeverity.CRITICAL,
        score=0.95,
    )

    patches = PatchPlanner.plan_patches([attack_result])
    tool_patches = [p for p in patches if p.patch_type == PatchType.TOOL_POLICY]
    assert len(tool_patches) > 0


def test_patch_has_diff():
    """Test patches include diff information."""
    attack_result = AttackResult(
        run_id="test",
        attempt_number=1,
        strategy_type=StrategyType.PROMPT_INJECTION,
        prompt="test",
        response="test",
        success=True,
        severity=AttackSeverity.HIGH,
        score=0.8,
    )

    patches = PatchPlanner.plan_patches([attack_result])
    assert patches[0].diff is not None
    assert len(patches[0].diff) > 0
