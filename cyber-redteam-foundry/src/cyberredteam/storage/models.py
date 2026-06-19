"""SQLite database models and ORM definitions."""

from datetime import datetime

from sqlalchemy import JSON, Column, DateTime, Float, Integer, String, create_engine
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


class AttackRecord(Base):
    """Stores individual attack attempts."""

    __tablename__ = "attacks"

    id = Column(Integer, primary_key=True)
    run_id = Column(String, index=True)
    attempt_number = Column(Integer)
    strategy_type = Column(String)
    prompt = Column(String)
    response = Column(String)
    success = Column(Integer)  # 0 or 1
    severity = Column(String)
    score = Column(Float)
    indicators = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    error = Column(String, nullable=True)


class PatchRecord(Base):
    """Stores defensive patches applied."""

    __tablename__ = "patches"

    id = Column(Integer, primary_key=True)
    run_id = Column(String, index=True)
    patch_id = Column(String, unique=True)
    patch_type = Column(String)
    target_component = Column(String)
    original_config = Column(JSON)
    patched_config = Column(JSON)
    diff = Column(String)
    applied = Column(Integer)  # 0 or 1
    retest_passed = Column(Integer)  # 0 or 1
    timestamp = Column(DateTime, default=datetime.utcnow)


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


def get_engine(db_path: str):
    """Create SQLAlchemy engine for the database."""
    return create_engine(f"sqlite:///{db_path}")


def init_db(db_path: str):
    """Initialize database with all tables."""
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    return engine
