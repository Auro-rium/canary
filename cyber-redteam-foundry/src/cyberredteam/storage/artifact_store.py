"""SQLAlchemy artifact storage.

The public ``SQLiteStore`` name is retained for compatibility with the
original local Canary engine. It now accepts either a SQLite path or a
SQLAlchemy database URL, allowing the same store implementation to run on
RDS PostgreSQL in the API and worker containers.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from cyberredteam.logging import setup_logging
from cyberredteam.schemas import AttackResult
from cyberredteam.storage.models import (
    AttackRecord,
    FindingRecord,
    LLMCallRecord,
    RunRecord,
    TraceRecord,
    VerdictRecord,
    init_db,
)

logger = setup_logging()


class SQLiteStore:
    """SQLite-backed storage for red team artifacts."""

    def __init__(self, db_path: Path | str):
        """
        Initialize storage.

        Args:
            db_path: SQLite database path or SQLAlchemy database URL
        """
        self.location = str(db_path)
        self.is_url = "://" in self.location
        self.db_path = Path(db_path) if not self.is_url else None
        if self.db_path is not None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self.engine = init_db(self.location)
        self.SessionLocal = sessionmaker(bind=self.engine)
        logger.info("Initialized artifact store at %s", self.location)

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
                technique_id=result.technique_id or result.strategy_type.value,
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

    # ------------------------------------------------------------------
    # Phase 3 — findings, verdicts, traces
    # ------------------------------------------------------------------

    def save_verdict(self, verdict_data: Dict[str, Any]) -> None:
        """Store an evaluator verdict record."""
        with self.SessionLocal() as session:
            record = VerdictRecord(
                verdict_id=verdict_data["verdict_id"],
                finding_id=verdict_data.get("finding_id"),
                run_id=verdict_data["run_id"],
                attempt_number=verdict_data.get("attempt_number", 0),
                deterministic_score=verdict_data.get("deterministic_score", 0.0),
                llm_judge_score=verdict_data.get("llm_judge_score", 0.0),
                consensus_score=verdict_data.get("consensus_score", 0.0),
                threshold_used=verdict_data.get("threshold_used", 0.5),
                verdict=verdict_data.get("verdict", "inconclusive"),
                confidence=verdict_data.get("confidence", "low"),
                rationale=verdict_data.get("rationale"),
                inconclusive_reason=verdict_data.get("inconclusive_reason"),
                asi_class_suggested=verdict_data.get("asi_class_suggested"),
                verdict_path=verdict_data.get("verdict_path"),
            )
            session.add(record)
            session.commit()
            logger.debug(f"Saved verdict {verdict_data['verdict_id']}")

    def save_trace(self, trace_data: Dict[str, Any]) -> None:
        """Store an attack trace record."""
        with self.SessionLocal() as session:
            record = TraceRecord(
                trace_id=trace_data["trace_id"],
                attempt_id=trace_data.get("attempt_id"),
                finding_id=trace_data.get("finding_id"),
                run_id=trace_data["run_id"],
                adversarial_input=trace_data.get("adversarial_input", ""),
                tool_calls_observed=trace_data.get("tool_calls_observed", []),
                target_response=trace_data.get("target_response", ""),
            )
            session.add(record)
            session.commit()
            logger.debug(f"Saved trace {trace_data['trace_id']}")

    def upsert_finding(self, finding_data: Dict[str, Any]) -> None:
        """Insert or update a finding row.

        On insert: sets first_seen_run, seen_in_runs=[run_id], status=open.
        On update: updates last_seen_run, appends run_id to seen_in_runs.
        Status is never changed here — use transition_finding_status().
        """
        from cyberredteam.storage.embedder import embed, semantic_similarity

        fid = finding_data["finding_id"]
        run_id = finding_data["run_id"]

        with self.SessionLocal() as session:
            existing = session.get(FindingRecord, fid)

            if existing is None:
                # Compute embedding for deduplication
                emb = embed(finding_data.get("adversarial_input", finding_data.get("finding_id", "")))

                # Check semantic similarity against open findings for same target
                if emb is not None:
                    similar_q = select(FindingRecord).where(
                        FindingRecord.target_id == finding_data.get("target_id", ""),
                        FindingRecord.status == "open",
                        FindingRecord.embedding.isnot(None),
                    )
                    for candidate in session.scalars(similar_q):
                        if candidate.embedding:
                            sim = semantic_similarity(emb, candidate.embedding)
                            if sim >= 0.92:
                                logger.warning(
                                    f"Potential duplicate finding: {fid} ~= {candidate.finding_id} "
                                    f"(similarity={sim:.3f}). Surfaced for review."
                                )
                                finding_data["_duplicate_candidate"] = candidate.finding_id

                record = FindingRecord(
                    finding_id=fid,
                    target_id=finding_data.get("target_id", ""),
                    component=finding_data.get("component", ""),
                    strategy=finding_data.get("strategy", ""),
                    asi_class=finding_data.get("asi_class", ""),
                    atlas_technique=finding_data.get("atlas_technique", ""),
                    severity=finding_data.get("severity", "info"),
                    status="open",
                    first_seen_run=run_id,
                    last_seen_run=run_id,
                    seen_in_runs=[run_id],
                    embedding=emb,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
                session.add(record)
                logger.info(f"Created finding {fid} (asi={finding_data.get('asi_class')})")
            else:
                # Append this run if not already present
                seen = list(existing.seen_in_runs or [])
                if run_id not in seen:
                    seen.append(run_id)
                existing.seen_in_runs = seen
                existing.last_seen_run = run_id
                existing.updated_at = datetime.utcnow()
                # Promote severity if this run found it worse
                sev_order = ["info", "low", "medium", "high", "critical"]
                new_sev = finding_data.get("severity", "info")
                cur_sev = existing.severity or "info"
                if sev_order.index(new_sev) > sev_order.index(cur_sev):
                    existing.severity = new_sev
                logger.info(f"Updated finding {fid} (last_seen_run={run_id})")

            session.commit()

    # Valid status transitions: maps current → allowed next states
    _VALID_TRANSITIONS: Dict[str, List[str]] = {
        "open":            ["wont_fix", "false_positive", "inconclusive"],
        "inconclusive":    ["open", "wont_fix", "false_positive"],
        "wont_fix":        [],
        "false_positive":  [],
    }

    def transition_finding_status(
        self,
        finding_id: str,
        new_status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Change a finding's lifecycle status with strict validation.

        Raises ValueError for illegal transitions or missing required metadata.
        """
        metadata = metadata or {}

        with self.SessionLocal() as session:
            finding = session.get(FindingRecord, finding_id)
            if finding is None:
                raise ValueError(f"Finding {finding_id} not found")

            current = finding.status or "open"
            allowed = self._VALID_TRANSITIONS.get(current, [])
            if new_status not in allowed:
                raise ValueError(
                    f"Illegal transition {current!r} → {new_status!r} for finding {finding_id}. "
                    f"Allowed from {current!r}: {allowed}"
                )

            if new_status in ("wont_fix", "false_positive"):
                if not metadata.get("reviewer_id"):
                    raise ValueError(f"{new_status} requires metadata['reviewer_id']")
                if not metadata.get("rationale"):
                    raise ValueError(f"{new_status} requires metadata['rationale']")

            finding.status = new_status
            finding.updated_at = datetime.utcnow()

            session.commit()
            logger.info(f"Finding {finding_id}: {current} → {new_status}")

    def get_findings(
        self,
        target_id: Optional[str] = None,
        asi_class: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> List[Dict]:
        """Paginated query of findings with optional filters."""
        with self.SessionLocal() as session:
            q = select(FindingRecord)
            if target_id:
                q = q.where(FindingRecord.target_id == target_id)
            if asi_class:
                q = q.where(FindingRecord.asi_class == asi_class)
            if status:
                q = q.where(FindingRecord.status == status)
            if severity:
                q = q.where(FindingRecord.severity == severity)
            q = q.order_by(FindingRecord.updated_at.desc())
            q = q.offset((page - 1) * page_size).limit(page_size)
            records = session.scalars(q).all()
            return [self._finding_to_dict(r) for r in records]

    def get_finding(self, finding_id: str) -> Optional[Dict]:
        """Single finding with its most recent verdict."""
        with self.SessionLocal() as session:
            finding = session.get(FindingRecord, finding_id)
            if finding is None:
                return None
            result = self._finding_to_dict(finding)

            # Attach most recent verdict
            vq = (
                select(VerdictRecord)
                .where(VerdictRecord.finding_id == finding_id)
                .order_by(VerdictRecord.timestamp.desc())
                .limit(1)
            )
            verdict = session.scalar(vq)
            if verdict:
                result["latest_verdict"] = {
                    "verdict_id": verdict.verdict_id,
                    "verdict": verdict.verdict,
                    "confidence": verdict.confidence,
                    "threshold_used": verdict.threshold_used,
                    "verdict_path": verdict.verdict_path,
                    "rationale": verdict.rationale,
                    "timestamp": verdict.timestamp.isoformat() if verdict.timestamp else None,
                }
            return result

    def get_finding_attempts(self, finding_id: str) -> List[Dict]:
        """All attack records linked to a finding across all runs."""
        with self.SessionLocal() as session:
            q = select(AttackRecord).where(AttackRecord.finding_id == finding_id)
            records = session.scalars(q).all()
            return [
                {
                    "id": r.id,
                    "run_id": r.run_id,
                    "attempt_number": r.attempt_number,
                    "strategy_type": r.strategy_type,
                    "success": bool(r.success),
                    "severity": r.severity,
                    "score": r.score,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                }
                for r in records
            ]

    def get_target_coverage(self, target_id: str) -> Dict:
        """Which ASI classes have been tested; which have open findings."""
        all_asi = [f"ASI0{i}" for i in range(1, 10)] + ["ASI10"]
        with self.SessionLocal() as session:
            q = select(FindingRecord).where(FindingRecord.target_id == target_id)
            findings = session.scalars(q).all()

        tested = {f.asi_class for f in findings if f.asi_class}
        open_by_class: Dict[str, int] = {}
        for f in findings:
            if f.status == "open" and f.asi_class:
                open_by_class[f.asi_class] = open_by_class.get(f.asi_class, 0) + 1

        return {
            "target_id": target_id,
            "tested_classes": sorted(tested),
            "untested_classes": [c for c in all_asi if c not in tested],
            "open_findings_by_class": open_by_class,
            "total_findings": len(findings),
            "open_findings": sum(1 for f in findings if f.status == "open"),
        }

    def get_target_trends(self, target_id: str, days: int = 30) -> List[Dict]:
        """Success rate per strategy per day for a target."""
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(days=days)
        with self.SessionLocal() as session:
            q = (
                select(AttackRecord)
                .where(
                    AttackRecord.target_id == target_id,
                    AttackRecord.timestamp >= cutoff,
                )
                .order_by(AttackRecord.timestamp)
            )
            records = session.scalars(q).all()

        by_day_strat: Dict[str, Dict[str, list]] = {}
        for r in records:
            day = r.timestamp.date().isoformat() if r.timestamp else "unknown"
            strat = r.strategy_type or "unknown"
            by_day_strat.setdefault(day, {}).setdefault(strat, []).append(bool(r.success))

        trends = []
        for day, strats in sorted(by_day_strat.items()):
            for strat, outcomes in strats.items():
                trends.append({
                    "date": day,
                    "strategy": strat,
                    "attempts": len(outcomes),
                    "successes": sum(outcomes),
                    "success_rate": sum(outcomes) / len(outcomes) if outcomes else 0.0,
                })
        return trends

    def get_run_findings(self, run_id: str) -> List[Dict]:
        """All findings first seen or updated in this run."""
        with self.SessionLocal() as session:
            q = select(FindingRecord).where(
                (FindingRecord.first_seen_run == run_id)
                | (FindingRecord.last_seen_run == run_id)
            )
            records = session.scalars(q).all()
            return [self._finding_to_dict(r) for r in records]

    @staticmethod
    def _finding_to_dict(r: FindingRecord) -> Dict:
        return {
            "finding_id": r.finding_id,
            "target_id": r.target_id,
            "component": r.component,
            "strategy": r.strategy,
            "asi_class": r.asi_class,
            "atlas_technique": r.atlas_technique,
            "severity": r.severity,
            "status": r.status,
            "first_seen_run": r.first_seen_run,
            "last_seen_run": r.last_seen_run,
            "seen_in_runs": r.seen_in_runs or [],
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }

    def close(self) -> None:
        """Close database connections."""
        self.engine.dispose()
