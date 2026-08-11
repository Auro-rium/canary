"""SQLite database models and ORM definitions."""

from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, Float, Integer, String, create_engine, text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class RunRecord(Base):
    """Stores metadata about each red team run."""

    __tablename__ = "runs"

    run_id = Column(String, primary_key=True)
    target_id = Column(String, index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    total_attacks = Column(Integer, default=0)
    successful_attacks = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)
    status = Column(String, default="running")  # running | completed | failed
    error = Column(String, nullable=True)


class AttackRecord(Base):
    """Stores individual attack attempts."""

    __tablename__ = "attacks"

    id = Column(Integer, primary_key=True)
    run_id = Column(String, index=True)
    target_id = Column(String, nullable=True, index=True)
    attempt_number = Column(Integer)
    strategy_type = Column(String)
    prompt = Column(String)
    response = Column(String)
    success = Column(Integer)  # 0 or 1
    severity = Column(String)
    score = Column(Float)
    score_threshold = Column(Float, default=0.5)
    finding_id = Column(String, nullable=True, index=True)
    indicators = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    error = Column(String, nullable=True)


class LLMCallRecord(Base):
    """Stores observability details about LLM calls."""

    __tablename__ = "llm_calls"

    id = Column(Integer, primary_key=True)
    agent_name = Column(String, index=True)
    deployment = Column(String)
    latency = Column(Float)
    input_hash = Column(String)
    output_hash = Column(String)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)


class FindingRecord(Base):
    """Canonical vulnerability finding, stable across campaigns."""

    __tablename__ = "findings"

    finding_id = Column(String, primary_key=True)
    target_id = Column(String, nullable=False, index=True)
    component = Column(String, nullable=True)
    strategy = Column(String, nullable=True)
    asi_class = Column(String, nullable=True, index=True)
    atlas_technique = Column(String, nullable=True)
    severity = Column(String, nullable=True)
    status = Column(String, default="open", index=True)
    first_seen_run = Column(String, nullable=True)
    last_seen_run = Column(String, nullable=True)
    seen_in_runs = Column(JSON, default=list)
    embedding = Column(JSON, nullable=True)
    trace_s3_uri = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class VerdictRecord(Base):
    """Evaluator verdict for a single attack attempt."""

    __tablename__ = "evaluator_verdicts"

    verdict_id = Column(String, primary_key=True)
    finding_id = Column(String, nullable=True, index=True)
    run_id = Column(String, index=True)
    attempt_number = Column(Integer)
    deterministic_score = Column(Float, default=0.0)
    llm_judge_score = Column(Float, default=0.0)
    consensus_score = Column(Float, default=0.0)
    threshold_used = Column(Float, default=0.5)
    verdict = Column(String)  # confirmed | unconfirmed | inconclusive | failed
    confidence = Column(String)  # high | medium | low
    rationale = Column(String, nullable=True)
    inconclusive_reason = Column(String, nullable=True)
    asi_class_suggested = Column(String, nullable=True)
    verdict_path = Column(String, nullable=True)  # consensus | deterministic_only | llm_only | heuristic_fallback
    timestamp = Column(DateTime, default=datetime.utcnow)


class TraceRecord(Base):
    """Verbatim attack trace for Phase 4 replay."""

    __tablename__ = "attack_traces"

    trace_id = Column(String, primary_key=True)
    attempt_id = Column(Integer, nullable=True, index=True)
    finding_id = Column(String, nullable=True, index=True)
    run_id = Column(String, index=True)
    adversarial_input = Column(String)  # raw prompt before sanitization
    tool_calls_observed = Column(JSON, default=list)
    target_response = Column(String)  # full unsanitized response
    captured_at = Column(DateTime, default=datetime.utcnow)


def get_engine(db_path: str):
    """Create SQLAlchemy engine for the database."""
    return create_engine(f"sqlite:///{db_path}")


def _migrate_columns(engine) -> None:
    """ADD new columns to existing tables without dropping data.

    SQLite does not support IF NOT EXISTS on ALTER TABLE, so we read
    the current column list via PRAGMA and skip columns that are
    already present.  New tables are created by create_all(); this
    function only handles column additions to *existing* tables.
    """
    migrations = {
        "attacks": [
            ("target_id",      "VARCHAR"),
            ("finding_id",     "VARCHAR"),
            ("score_threshold","REAL DEFAULT 0.5"),
            ("error",          "TEXT"),
        ],
        "findings": [
            ("embedding",      "TEXT"),
            ("trace_s3_uri",   "VARCHAR"),
        ],
        "runs": [
            ("error", "TEXT"),
        ],
        "evaluator_verdicts": [
            ("asi_class_suggested", "VARCHAR"),
            ("inconclusive_reason", "TEXT"),
        ],
        "attack_traces": [
            ("finding_id",     "VARCHAR"),
        ],
    }
    with engine.connect() as conn:
        for table, cols in migrations.items():
            # Skip migration for tables that may not exist yet (create_all handles them)
            try:
                rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            except Exception:
                continue
            if not rows:
                continue
            existing = {row[1] for row in rows}  # column_name is index 1
            for col_name, col_type in cols:
                if col_name not in existing:
                    conn.execute(
                        text(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
                    )
            conn.commit()


def init_db(db_path: str):
    """Initialize database with all tables, then migrate missing columns."""
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    _migrate_columns(engine)
    return engine
