"""SQLite artifact storage."""

from pathlib import Path
from typing import Dict, List, Optional

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
            stmt = select(RunRecord).where(RunRecord.run_id == run_id)
            existing = session.scalar(stmt)
            if existing:
                logger.info(f"Run {run_id} already exists in DB, skipping insert")
                return
            run = RunRecord(run_id=run_id, target_id=target_id)
            session.add(run)
            session.commit()
            logger.info(f"Saved run start: {run_id}")

    def save_attack_result(self, result: AttackResult) -> None:
        """Store an attack result."""
        with self.SessionLocal() as session:
            attack = AttackRecord(
                run_id=result.run_id,
                target_id=result.target_id,
                attempt_number=result.attempt_number,
                strategy_type=result.strategy_type.value,
                prompt=result.prompt,
                response=result.response,
                success=1 if result.success else 0,
                severity=result.severity.value,
                score=result.score,
                score_threshold=result.score_threshold,
                finding_id=result.finding_id or None,
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
                finding_id=result.finding_id or None,
                retest_prompt=result.retest_prompt or None,
                retest_response=result.retest_response or None,
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

    def get_open_findings(self, target_id: Optional[str] = None) -> List[Dict]:
        """Return findings that have no passing retest — open issues across all runs.

        A finding is "open" when its finding_id appears in patches but none of
        those patches have retest_passed=1.  This lets the next campaign's
        strategist avoid re-discovering the same vulnerabilities from scratch.

        Args:
            target_id: If given, restrict to attacks on this target.

        Returns:
            List of dicts with finding_id, strategy_type, target_component,
            run_id (most recent), and patch_count.
        """
        with self.SessionLocal() as session:
            patch_q = select(PatchRecord).where(PatchRecord.finding_id.isnot(None))
            patches = session.scalars(patch_q).all()

            # Group by finding_id; a finding is open iff no patch has retest_passed
            from collections import defaultdict
            grouped: dict = defaultdict(list)
            for p in patches:
                grouped[p.finding_id].append(p)

            open_findings = []
            for fid, patch_list in grouped.items():
                if any(p.retest_passed for p in patch_list):
                    continue  # at least one passing retest → closed
                latest = max(patch_list, key=lambda p: p.timestamp or 0)

                # Optionally filter by target_id via the associated attack record
                if target_id:
                    atk_q = select(AttackRecord).where(
                        AttackRecord.finding_id == fid,
                        AttackRecord.target_id == target_id,
                    )
                    if not session.scalar(atk_q):
                        continue

                open_findings.append({
                    "finding_id": fid,
                    "target_component": latest.target_component,
                    "patch_type": latest.patch_type,
                    "run_id": latest.run_id,
                    "patch_count": len(patch_list),
                    "last_seen": latest.timestamp.isoformat() if latest.timestamp else None,
                })

            return open_findings

    def close(self) -> None:
        """Close database connections."""
        self.engine.dispose()
