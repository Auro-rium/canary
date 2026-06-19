"""SQLite artifact storage."""

from pathlib import Path
from typing import List

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackResult, PatchResult
from cyberredteam.storage.models import (
    AttackRecord,
    LLMCallRecord,
    PatchRecord,
    RunRecord,
    init_db,
)

logger = setup_logging()


class SQLiteStore:
    """SQLite-backed storage for red team artifacts."""

    def __init__(self, db_path: Path):
        """
        Initialize storage.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self.engine = init_db(str(self.db_path))
        self.SessionLocal = sessionmaker(bind=self.engine)
        logger.info(f"Initialized SQLite store at {self.db_path}")

    def save_run_start(self, run_id: str, target_id: str) -> None:
        """Record the start of a run."""
        with self.SessionLocal() as session:
            run = RunRecord(run_id=run_id, target_id=target_id)
            session.add(run)
            session.commit()
            logger.info(f"Saved run start: {run_id}")

    def save_attack_result(self, result: AttackResult) -> None:
        """Store an attack result."""
        with self.SessionLocal() as session:
            attack = AttackRecord(
                run_id=result.run_id,
                attempt_number=result.attempt_number,
                strategy_type=result.strategy_type.value,
                prompt=result.prompt,
                response=result.response,
                success=1 if result.success else 0,
                severity=result.severity.value,
                score=result.score,
                indicators=result.indicators,
                error=result.error,
            )
            session.add(attack)
            session.commit()
            logger.debug(f"Saved attack result for run {result.run_id}")

    def save_patch_result(self, result: PatchResult) -> None:
        """Store a patch result."""
        with self.SessionLocal() as session:
            patch = PatchRecord(
                run_id=result.run_id,
                patch_id=result.patch_id,
                patch_type=result.patch_type.value,
                target_component=result.target_component,
                original_config=result.original_config,
                patched_config=result.patched_config,
                diff=result.diff,
                applied=1 if result.applied else 0,
                retest_passed=1 if result.retest_passed else 0,
            )
            session.add(patch)
            session.commit()
            logger.debug(f"Saved patch result: {result.patch_id}")

    def save_llm_call(
        self,
        agent_name: str,
        deployment: str,
        latency: float,
        input_hash: str,
        output_hash: str,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> None:
        """Store an LLM call observability record."""
        with self.SessionLocal() as session:
            record = LLMCallRecord(
                agent_name=agent_name,
                deployment=deployment,
                latency=latency,
                input_hash=input_hash,
                output_hash=output_hash,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )
            session.add(record)
            session.commit()
            logger.debug(f"Saved LLM call record for agent {agent_name}")

    def get_run_attacks(self, run_id: str) -> List[AttackRecord]:
        """Retrieve all attacks for a run."""
        with self.SessionLocal() as session:
            stmt = select(AttackRecord).where(AttackRecord.run_id == run_id)
            return session.scalars(stmt).all()

    def get_run_patches(self, run_id: str) -> List[PatchRecord]:
        """Retrieve all patches for a run."""
        with self.SessionLocal() as session:
            stmt = select(PatchRecord).where(PatchRecord.run_id == run_id)
            return session.scalars(stmt).all()

    def update_run_complete(
        self,
        run_id: str,
        total_attacks: int,
        successful_attacks: int,
    ) -> None:
        """Mark a run as complete."""
        with self.SessionLocal() as session:
            stmt = select(RunRecord).where(RunRecord.run_id == run_id)
            run = session.scalar(stmt)
            if run:
                run.total_attacks = total_attacks
                run.successful_attacks = successful_attacks
                run.success_rate = (
                    successful_attacks / total_attacks if total_attacks > 0 else 0.0
                )
                run.status = "completed"
                session.commit()
                logger.info(f"Updated run complete: {run_id}")

    def close(self) -> None:
        """Close database connections."""
        self.engine.dispose()
