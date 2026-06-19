"""Orchestrator state machine for red team runs."""

from datetime import datetime
from enum import Enum

from cyberredteam.logging import setup_logging
from cyberredteam.schemas import RunConfig

logger = setup_logging()


class RunState(str, Enum):
    """State of a red team run."""

    INITIALIZED = "initialized"
    EXECUTING = "executing"
    EVALUATING = "evaluating"
    PATCHING = "patching"
    RETESTING = "retesting"
    COMPLETE = "complete"
    FAILED = "failed"


class StateMachine:
    """State machine for orchestrating red team runs."""

    def __init__(self, run_config: RunConfig):
        """
        Initialize state machine.

        Args:
            run_config: Configuration for the run
        """
        self.config = run_config
        self.current_state = RunState.INITIALIZED
        self.state_history = [(datetime.utcnow(), RunState.INITIALIZED)]

    def transition(self, new_state: RunState) -> bool:
        """
        Attempt to transition to a new state.

        Args:
            new_state: Target state

        Returns:
            True if transition was valid, False otherwise
        """
        valid_transitions = {
            RunState.INITIALIZED: [RunState.EXECUTING, RunState.FAILED],
            RunState.EXECUTING: [RunState.EVALUATING, RunState.FAILED],
            RunState.EVALUATING: [RunState.PATCHING, RunState.COMPLETE, RunState.FAILED],
            RunState.PATCHING: [RunState.RETESTING, RunState.FAILED],
            RunState.RETESTING: [RunState.EXECUTING, RunState.COMPLETE, RunState.FAILED],
            RunState.COMPLETE: [],
            RunState.FAILED: [],
        }

        if new_state not in valid_transitions.get(self.current_state, []):
            logger.warning(
                f"Invalid transition: {self.current_state} -> {new_state}"
            )
            return False

        logger.info(f"Transitioning: {self.current_state} -> {new_state}")
        self.current_state = new_state
        self.state_history.append((datetime.utcnow(), new_state))
        return True

    def get_state_duration(self, state: RunState) -> float:
        """
        Get time spent in a state (in seconds).

        Args:
            state: State to query

        Returns:
            Duration in seconds
        """
        entries = [
            (t, s) for t, s in self.state_history if s == state
        ]
        if not entries:
            return 0.0

        # Find first and last occurrence
        start_time = entries[0][0]
        end_time = entries[-1][0]

        return (end_time - start_time).total_seconds()
