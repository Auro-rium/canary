"""LangGraph-based red team orchestrator.

``GraphOrchestrator`` is the single entry-point for running and
resuming red-team workflows.  It:

*  Initialises ``RedTeamState`` from a ``RunConfig``.
*  Compiles the state graph with SQLite checkpointing.
*  Invokes the graph with a ``thread_id`` (= ``run_id``) so each run
   gets its own checkpoint timeline.
*  Persists all artifacts (attacks, patches) to the separate SQLite
   artifact store after the graph completes.
*  Generates and saves a Mermaid visualisation.
"""

import time
from pathlib import Path
from typing import Any, Dict, Optional

from cyberredteam.langgraph.graph import compile_graph, get_mermaid_graph
from cyberredteam.langgraph.state import RedTeamState
from cyberredteam.logging import setup_logging
from cyberredteam.schemas import RunConfig
from cyberredteam.storage.artifact_store import SQLiteStore

logger = setup_logging()

# Default checkpoint database path (relative to project root)
_DEFAULT_CHECKPOINT_DB = "runs/checkpoints.db"


class GraphOrchestrator:
    """LangGraph-based orchestrator for red team runs."""

    def __init__(
        self,
        config: RunConfig,
        db_path: Path,
        report_dir: Path,
        max_iterations: int = 3,
        checkpoint_db_path: Optional[str] = None,
    ):
        """Initialise the graph orchestrator.

        Args:
            config: ``RunConfig`` with attack parameters.
            db_path: Path to the SQLite *artifact* database.
            report_dir: Directory for report output.
            max_iterations: Max defender→attacker→evaluator cycles.
            checkpoint_db_path: Path to the SQLite *checkpoint*
                database.  Defaults to ``runs/checkpoints.db``.
        """
        self.config = config
        self.db_path = Path(db_path)
        self.report_dir = Path(report_dir)
        self.max_iterations = max_iterations

        # Checkpoint DB — separate from artifact DB
        self.checkpoint_db_path = checkpoint_db_path or _DEFAULT_CHECKPOINT_DB
        Path(self.checkpoint_db_path).parent.mkdir(parents=True, exist_ok=True)

        # Artifact store
        self.store = SQLiteStore(self.db_path)

        # Compile graph with SQLite checkpointing
        self.graph = compile_graph(self.checkpoint_db_path)

        logger.info(
            f"Initialised GraphOrchestrator for run {config.run_id} "
            f"(checkpoint_db={self.checkpoint_db_path})"
        )

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        """Execute the red team workflow via LangGraph.

        Returns:
            Summary dict with run results, report paths, etc.
        """
        try:
            logger.info(
                f"Starting LangGraph orchestration for {self.config.run_id}"
            )
            start_time = time.time()

            # Record run start in artifact store
            self.store.save_run_start(
                self.config.run_id, self.config.target_id,
            )

            # Build initial state
            initial_state: RedTeamState = {
                "run_id": self.config.run_id,
                "target_id": self.config.target_id,
                "description": self.config.description,
                "seed": self.config.seed,
                "status": "running",
                "strategies": [s.value for s in self.config.strategy_types],
                "max_iterations": self.max_iterations,
                "max_attempts_per_strategy": 2,
                "timeout_seconds": self.config.timeout_seconds,
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
                "start_time": start_time,
                "end_time": None,
                "error": None,
                "log_messages": [],
            }

            # LangGraph invocation config with thread_id for checkpointing
            graph_config = {
                "configurable": {
                    "thread_id": self.config.run_id,
                },
            }

            # Execute graph
            logger.info(
                f"Executing graph for run {self.config.run_id} "
                f"(thread_id={self.config.run_id})"
            )
            final_state = self.graph.invoke(initial_state, config=graph_config)

            # ── Post-processing ─────────────────────────────────────
            self._persist_artifacts(final_state)

            end_time = time.time()
            execution_time = end_time - start_time

            attack_results = final_state.get("attack_results", [])
            patch_results = final_state.get("patch_results", [])
            successful = sum(1 for r in attack_results if r.success)

            logger.info(
                f"Completed run {self.config.run_id}: "
                f"{successful} successful attacks, "
                f"{len(patch_results)} patches, "
                f"{execution_time:.1f}s"
            )

            report_paths = final_state.get("report_paths", {})
            return {
                "run_id": self.config.run_id,
                "target_id": self.config.target_id,
                "total_attacks": len(attack_results),
                "successful_attacks": successful,
                "patches_applied": len(patch_results),
                "success_rate": (
                    successful / len(attack_results) if attack_results else 0
                ),
                "markdown_report": report_paths.get("markdown", ""),
                "json_report": report_paths.get("json", ""),
                "execution_time": execution_time,
                "iterations": final_state.get("iteration", 0),
                "scores": final_state.get("scores", {}),
                "log_messages": final_state.get("log_messages", []),
            }

        except Exception as exc:
            logger.error(f"LangGraph orchestration failed: {exc}")
            raise

    def get_state(self) -> Optional[Dict[str, Any]]:
        """Inspect the current checkpoint state for this run.

        Returns:
            The latest state snapshot, or ``None`` if no checkpoint
            exists.
        """
        graph_config = {
            "configurable": {
                "thread_id": self.config.run_id,
            },
        }
        try:
            snapshot = self.graph.get_state(graph_config)
            return snapshot.values if snapshot else None
        except Exception as exc:
            logger.warning(f"Could not load state: {exc}")
            return None

    @staticmethod
    def get_graph_visualization(
        checkpoint_db_path: Optional[str] = None,
    ) -> str:
        """Get Mermaid visualisation of the graph.

        Returns:
            Mermaid diagram string.
        """
        return get_mermaid_graph(checkpoint_db_path)

    # -----------------------------------------------------------------
    # Internals
    # -----------------------------------------------------------------

    def _persist_artifacts(self, final_state: Dict[str, Any]) -> None:
        """Save all attack results and patches to the artifact store."""
        attack_results = final_state.get("attack_results", [])
        patch_results = final_state.get("patch_results", [])

        for result in attack_results:
            self.store.save_attack_result(result)

        for patch in patch_results:
            try:
                self.store.save_patch_result(patch)
            except Exception:
                # Duplicate patch_id across iterations — skip gracefully
                logger.debug(
                    f"Skipping duplicate patch {patch.patch_id}"
                )

        successful = sum(1 for r in attack_results if r.success)
        self.store.update_run_complete(
            run_id=self.config.run_id,
            total_attacks=len(attack_results),
            successful_attacks=successful,
        )

        logger.info(
            f"Persisted {len(attack_results)} attacks and "
            f"{len(patch_results)} patches to artifact store"
        )
