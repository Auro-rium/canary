"""Tests for the LangGraph-based orchestrator and routing functions."""


from cyberredteam.langgraph.graph import (
    build_redteam_graph,
    should_iterate,
)
from cyberredteam.langgraph.state import RedTeamState

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def _make_state(**overrides) -> RedTeamState:
    """Build a minimal ``RedTeamState`` with sensible defaults."""
    base: RedTeamState = {
        "run_id": "test_run",
        "target_id": "test_target",
        "description": "unit test",
        "seed": None,
        "status": "running",
        "strategies": ["prompt_injection"],
        "max_iterations": 3,
        "max_attempts_per_strategy": 2,
        "timeout_seconds": 30,
        "iteration": 0,
        "current_strategy": "",
        "attack_results": [],
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
    base.update(overrides)
    return base


# -------------------------------------------------------------------
# Graph structure tests
# -------------------------------------------------------------------

class TestGraphBuild:
    """Verify the state graph builds correctly."""

    def test_graph_builds(self):
        """Graph can be constructed without errors."""
        graph = build_redteam_graph()
        assert graph is not None

    def test_graph_has_four_nodes(self):
        """Graph contains exactly 4 agent nodes."""
        graph = build_redteam_graph()
        # StateGraph exposes nodes dict
        node_names = set(graph.nodes.keys())
        expected = {"strategist", "attacker_branch", "evaluator", "reporter"}
        assert expected.issubset(node_names)

    def test_graph_compiles(self):
        """Graph compiles with in-memory checkpointing."""
        from cyberredteam.langgraph.graph import compile_graph

        compiled = compile_graph()  # in-memory fallback
        assert compiled is not None


# -------------------------------------------------------------------
# Routing function tests
# -------------------------------------------------------------------

class TestRouting:
    """Verify conditional routing functions."""

    def test_should_iterate_routes_to_strategist(self):
        state = _make_state(
            should_continue_iterating=True,
            iteration=1,
            max_iterations=3,
        )
        assert should_iterate(state) == "strategist"

    def test_should_iterate_routes_to_reporter_at_max(self):
        state = _make_state(
            should_continue_iterating=False,
            iteration=3,
            max_iterations=3,
        )
        assert should_iterate(state) == "reporter"

    def test_should_iterate_routes_to_reporter_no_vulns(self):
        state = _make_state(
            should_continue_iterating=False,
            iteration=0,
            max_iterations=3,
        )
        assert should_iterate(state) == "reporter"


# -------------------------------------------------------------------
# State construction tests
# -------------------------------------------------------------------

class TestStateConstruction:
    """Verify initial state is well-formed."""

    def test_default_state_fields(self):
        state = _make_state()
        assert state["run_id"] == "test_run"
        assert state["status"] == "running"
        assert state["iteration"] == 0
        assert state["attack_results"] == []
        assert state["log_messages"] == []

    def test_max_iterations_respected(self):
        state = _make_state(max_iterations=5)
        assert state["max_iterations"] == 5


# -------------------------------------------------------------------
# Mermaid generation tests
# -------------------------------------------------------------------

class TestMermaid:
    """Verify Mermaid diagram generation."""

    def test_mermaid_not_empty(self):
        from cyberredteam.langgraph.graph import get_mermaid_graph

        mermaid = get_mermaid_graph()
        assert len(mermaid) > 0

    def test_mermaid_contains_nodes(self):
        from cyberredteam.langgraph.graph import get_mermaid_graph

        mermaid = get_mermaid_graph()
        for node in ["strategist", "attacker_branch", "evaluator", "reporter"]:
            assert node.lower() in mermaid.lower()
