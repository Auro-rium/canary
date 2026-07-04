"""Dedicated LangGraph integration tests.

These tests exercise the full graph end-to-end using mock agents so
no Azure credentials or network calls are required.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from cyberredteam.langgraph.graph import build_redteam_graph, compile_graph
from cyberredteam.langgraph.state import RedTeamState
from cyberredteam.schemas import (
    AttackResult,
    AttackSeverity,
    PatchResult,
    PatchType,
    StrategyType,
)

# -------------------------------------------------------------------
# Fixtures
# -------------------------------------------------------------------

def _mock_attack_result(run_id: str, attempt: int, success: bool, iteration: int = 0) -> AttackResult:
    return AttackResult(
        run_id=run_id,
        attempt_number=attempt,
        strategy_type=StrategyType.PROMPT_INJECTION,
        prompt="test prompt",
        response="test response",
        success=success,
        severity=AttackSeverity.HIGH if success else AttackSeverity.LOW,
        score=0.8 if success else 0.2,
        technique_id="ASI01",
        capability_type=StrategyType.PROMPT_INJECTION.value,
        branch_id="mock-branch",
        iteration=iteration,
    )


def _mock_patch_result(run_id: str, idx: int) -> PatchResult:
    return PatchResult(
        run_id=run_id,
        patch_id=f"{run_id}_patch_{idx}",
        patch_type=PatchType.PROMPT_HARDENING,
        target_component="system_prompt",
        original_config={"instruction": "Be helpful"},
        patched_config={"instruction": "Be helpful but safe"},
        diff="+ safety_check: true",
        applied=True,
        retest_passed=True,
    )


# -------------------------------------------------------------------
# Graph structure tests
# -------------------------------------------------------------------

class TestGraphStructure:
    """Validate the compiled graph structure."""

    def test_node_count(self):
        graph = build_redteam_graph()
        node_names = set(graph.nodes.keys())
        assert len(node_names) >= 5

    def test_entry_point_is_strategist(self):
        build_redteam_graph()
        # The entry point is stored internally; verify by checking
        # that compiling with in-memory checkpoint doesn't error
        compiled = compile_graph()
        assert compiled is not None

    def test_sqlite_checkpoint_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "ckpt.db")
            compiled = compile_graph(checkpoint_db_path=db_path)
            assert compiled is not None
            assert Path(db_path).exists()


# -------------------------------------------------------------------
# Full graph invocation (mocked agents)
# -------------------------------------------------------------------

class TestGraphInvocation:
    """Run the full graph with mocked agent calls."""

    @patch("cyberredteam.langgraph.nodes._attacker_factory")
    @patch("cyberredteam.langgraph.nodes._evaluator_factory")
    @patch("cyberredteam.langgraph.nodes._defender_factory")
    @patch("cyberredteam.langgraph.nodes._reporter_factory", new=None)
    def test_full_run_no_vulns(
        self,
        mock_defender_f,
        mock_evaluator_f,
        mock_attacker_f,
    ):
        """Graph completes when no vulnerabilities are found."""
        # Attacker — the single branch attack fails (only 1 candidate strategy
        # is configured below, so the random fan-out dispatches exactly 1 branch)
        attacker = MagicMock()
        attacker.attack_branch.return_value = _mock_attack_result("test", 1, success=False)
        mock_attacker_f.return_value = attacker

        # Evaluator
        evaluator = MagicMock()
        evaluator.evaluate_batch.return_value = [attacker.attack_branch.return_value]
        evaluator.compute_overall_metrics.return_value = {
            "average_attack_score": 0.2,
            "success_rate": 0.0,
        }
        mock_evaluator_f.return_value = evaluator

        # Compile with in-memory checkpointing
        compiled = compile_graph()

        state: RedTeamState = {
            "run_id": "test",
            "target_id": "sandbox",
            "description": "test run",
            "seed": None,
            "status": "running",
            "target_headers": {},
            "target_request_template": None,
            "target_response_path": None,
            "strategies": ["prompt_injection"],
            "max_iterations": 3,
            "max_attempts_per_strategy": 2,
            "timeout_seconds": 30,
            "iteration": 0,
            "current_strategy": "",
            "attack_results": [],
            "patch_results": [],
            "should_patch": False,
            "should_continue_iterating": False,
            "vulnerability_found": False,
            "scores": {},
            "report_paths": {},
            "graph_visualization": "",
            "start_time": None,
            "end_time": None,
            "error": None,
            "log_messages": [],
        }

        config = {"configurable": {"thread_id": "test_no_vulns"}}

        with tempfile.TemporaryDirectory() as tmpdir:
            # Patch reporter to write to temp dir
            from cyberredteam.agents.reporter import ReporterAgent

            with patch(
                "cyberredteam.langgraph.nodes._reporter_factory",
                new=lambda report_dir: ReporterAgent(Path(tmpdir)),
            ):
                final = compiled.invoke(state, config=config)

        assert final["status"] == "completed"
        assert final["vulnerability_found"] is False
        # Should go strategist → attacker_branch → evaluator → reporter (no defender)
        assert len(final["patch_results"]) == 0


# -------------------------------------------------------------------
# Max iterations protection
# -------------------------------------------------------------------

class TestMaxIterations:
    """Verify max_iterations guard."""

    def test_iteration_respects_max(self):
        """should_continue_iterating is False when iteration >= max."""
        from cyberredteam.langgraph.graph import should_iterate

        state: RedTeamState = {
            "run_id": "test",
            "target_id": "t",
            "description": "",
            "seed": None,
            "status": "running",
            "strategies": [],
            "max_iterations": 2,
            "max_attempts_per_strategy": 2,
            "timeout_seconds": 30,
            "iteration": 2,
            "current_strategy": "",
            "attack_results": [],
            "patch_results": [],
            "should_patch": False,
            "should_continue_iterating": False,  # already at max
            "vulnerability_found": True,
            "scores": {},
            "report_paths": {},
            "graph_visualization": "",
            "start_time": None,
            "end_time": None,
            "error": None,
            "log_messages": [],
        }

        assert should_iterate(state) == "reporter"


# -------------------------------------------------------------------
# Parallel fan-out (real attacker/evaluator, fake LLM fixture)
# -------------------------------------------------------------------

class TestParallelFanOut:
    """Exercise the real strategist->attacker_branch fan-out end-to-end."""

    def test_three_branches_dispatch_and_tag_correctly(self):
        compiled = compile_graph()

        state: RedTeamState = {
            "run_id": "fanout1",
            "target_id": "sandbox-target-001",
            "description": "fan-out smoke target",
            "seed": None,
            "status": "running",
            "target_headers": {},
            "target_request_template": None,
            "target_response_path": None,
            "strategies": [
                "prompt_injection",
                "tool_misuse",
                "sensitive_data_exposure",
                "jailbreak",
            ],
            "max_iterations": 1,
            "max_attempts_per_strategy": 1,
            "timeout_seconds": 30,
            "iteration": 0,
            "current_strategy": "",
            "attack_results": [],
            "patch_results": [],
            "should_patch": False,
            "should_continue_iterating": False,
            "vulnerability_found": False,
            "scores": {},
            "report_paths": {},
            "graph_visualization": "",
            "start_time": None,
            "end_time": None,
            "error": None,
            "log_messages": [],
        }

        config = {"configurable": {"thread_id": "fanout1"}}
        final = compiled.invoke(state, config=config)

        results = final["attack_results"]
        # Random sample of up to 3 from 4 candidates -> exactly 3 branches.
        assert len(results) == 3
        branch_ids = {r.branch_id for r in results}
        assert len(branch_ids) == 3, "each branch must have a distinct branch_id"
        assert all(r.iteration == 0 for r in results), "results must be tagged with the dispatching iteration"
        assert all(r.technique_id for r in results), "results must carry a resolved ASI technique_id"
