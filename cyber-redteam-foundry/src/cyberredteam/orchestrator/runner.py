"""Main orchestrator for red team runs.

.. deprecated::
    This module is deprecated.  Use
    ``cyberredteam.langgraph.GraphOrchestrator`` instead.
"""

from datetime import datetime
from pathlib import Path

from cyberredteam.agents.attacker import AttackerAgent
from cyberredteam.agents.defender import DefenderAgent
from cyberredteam.agents.evaluator import EvaluatorAgent
from cyberredteam.agents.reporter import ReporterAgent
from cyberredteam.agents.strategist import StrategistAgent
from cyberredteam.logging import setup_logging
from cyberredteam.orchestrator.state_machine import RunState, StateMachine
from cyberredteam.schemas import RunConfig
from cyberredteam.storage.artifact_store import SQLiteStore

logger = setup_logging()


class RedTeamOrchestrator:
    """Orchestrates the full red team attack loop."""

    def __init__(
        self,
        config: RunConfig,
        db_path: Path,
        report_dir: Path,
    ):
        """
        Initialize orchestrator.

        Args:
            config: RunConfig with attack parameters
            db_path: Path to SQLite database
            report_dir: Directory for report output
        """
        self.config = config
        self.db_path = Path(db_path)
        self.report_dir = Path(report_dir)

        # Initialize storage
        self.store = SQLiteStore(self.db_path)

        # Initialize state machine
        self.state_machine = StateMachine(config)

        # Initialize agents
        self.strategist = StrategistAgent()
        self.attacker = AttackerAgent(use_foundry=True)
        self.evaluator = EvaluatorAgent()
        self.defender = DefenderAgent()
        self.reporter = ReporterAgent(self.report_dir)

        # Run tracking
        self.start_time = None
        self.end_time = None

    def run(self) -> dict:
        """
        Execute the full red team attack loop.

        Returns:
            Summary dict with results
        """
        try:
            logger.info(f"Starting red team run: {self.config.run_id}")
            self.start_time = datetime.utcnow()

            # Record run start
            self.store.save_run_start(self.config.run_id, self.config.target_id)

            # Phase 1: Strategy selection
            self.state_machine.transition(RunState.EXECUTING)
            strategies = self.strategist.select_strategies(
                target_id=self.config.target_id,
                risk_appetite="medium",
                count=3,
            )
            logger.info(f"Selected {len(strategies)} attack strategies")

            # Phase 2: Attack execution
            attack_results = self.attacker.batch_attack(
                run_id=self.config.run_id,
                target_id=self.config.target_id,
                strategies=strategies,
                max_attempts_per_strategy=2,
            )
            logger.info(f"Executed {len(attack_results)} attacks")

            # Save attack results
            for result in attack_results:
                self.store.save_attack_result(result)

            # Phase 3: Evaluation
            self.state_machine.transition(RunState.EVALUATING)
            evaluated_results = self.evaluator.evaluate_batch(attack_results)
            logger.info("Evaluated all attack results")

            # Phase 4: Patch planning & application
            self.state_machine.transition(RunState.PATCHING)
            patches = self.defender.plan_defenses(evaluated_results)
            applied_patches = self.defender.apply_patches(patches)
            logger.info(f"Applied {len(applied_patches)} patches")

            # Save patch results
            for patch in applied_patches:
                self.store.save_patch_result(patch)

            # Phase 5: Retest after patches
            self.state_machine.transition(RunState.RETESTING)
            for patch in applied_patches:
                # Re-execute original attacks to verify patches work
                prompts = [r.prompt for r in evaluated_results]
                self.defender.retest_after_patch(patch, prompts)

            logger.info("Completed retest phase")

            # Phase 6: Report generation
            self.state_machine.transition(RunState.COMPLETE)
            self.end_time = datetime.utcnow()

            report = self.reporter.generate_report(
                run_id=self.config.run_id,
                target_id=self.config.target_id,
                attack_results=evaluated_results,
                patches=applied_patches,
                start_time=self.start_time,
                end_time=self.end_time,
            )

            # Write reports
            md_report = self.reporter.write_markdown(report)
            json_report = self.reporter.write_json(report)

            # Update database
            self.store.update_run_complete(
                run_id=self.config.run_id,
                total_attacks=len(evaluated_results),
                successful_attacks=sum(1 for r in evaluated_results if r.success),
            )

            logger.info(
                f"Completed red team run {self.config.run_id}: "
                f"{sum(1 for r in evaluated_results if r.success)} successful attacks"
            )

            return {
                "run_id": self.config.run_id,
                "target_id": self.config.target_id,
                "total_attacks": len(evaluated_results),
                "successful_attacks": sum(1 for r in evaluated_results if r.success),
                "patches_applied": len(applied_patches),
                "success_rate": (
                    sum(1 for r in evaluated_results if r.success)
                    / len(evaluated_results)
                    if evaluated_results
                    else 0
                ),
                "markdown_report": str(md_report),
                "json_report": str(json_report),
                "execution_time": (self.end_time - self.start_time).total_seconds(),
            }

        except Exception as e:
            logger.error(f"Red team run failed: {e}")
            self.state_machine.transition(RunState.FAILED)
            raise
