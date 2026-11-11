"""Alembic migrations: up/down on SQLite, and on Postgres when configured."""

from __future__ import annotations

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from cryptography.fernet import Fernet
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from storage_v2_support import migrate_down, migrate_up, pg_url

from cyberredteam.storage.v2 import orm
from cyberredteam.storage.v2.db import make_engine

TABLES = {
    "targets", "target_secrets", "target_verification", "campaigns", "conversations", "turns",
    "judge_votes", "verdicts", "technique_results", "findings", "finding_events", "audit_log",
    "budget_ledger",
}

pg_only = pytest.mark.skipif(not pg_url(), reason="CANARY_TEST_DATABASE_URL not set")


def _tables(engine):
    return set(inspect(engine).get_table_names()) - {"alembic_version"}


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pg_only)])
def url(request, tmp_path):
    u = pg_url() if request.param == "postgres" else f"sqlite:///{tmp_path / 'm.db'}"
    if request.param == "postgres":
        migrate_down(u)
    yield u
    if request.param == "postgres":
        migrate_down(u)


def test_upgrade_downgrade_upgrade(url):
    engine = make_engine(url)
    assert _tables(engine) == set()
    migrate_up(url)
    assert _tables(engine) == TABLES
    migrate_down(url)
    assert _tables(engine) == set()
    migrate_up(url)
    assert _tables(engine) == TABLES
    engine.dispose()


def test_migrated_schema_matches_orm(url):
    migrate_up(url)
    engine = make_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), orm.Base.metadata)
    engine.dispose()
    if engine.dialect.name != "postgresql":  # HNSW index exists only on Postgres
        diff = [d for d in diff if "ix_findings_embedding_hnsw" not in str(d)]
    assert diff == [], diff


def test_foreign_keys_enforced(url, monkeypatch):
    monkeypatch.setenv("CANARY_ENCRYPTION_KEY", Fernet.generate_key().decode())
    migrate_up(url)
    engine = make_engine(url)
    with pytest.raises(IntegrityError):
        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO campaigns (campaign_id, target_id, policy, status, created_at) "
                "VALUES ('c', 'no-such-target', '{}', 'queued', CURRENT_TIMESTAMP)"))
    engine.dispose()


@pg_only
def test_pgvector_column_and_extension():
    url = pg_url()
    migrate_down(url)
    migrate_up(url)
    engine = make_engine(url)
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT 1 FROM pg_extension WHERE extname='vector'")).scalar()
            typ = conn.execute(text(
                "SELECT format_type(atttypid, atttypmod) FROM pg_attribute "
                "WHERE attrelid='findings'::regclass AND attname='embedding'")).scalar()
        assert typ == "vector(384)"
    finally:
        engine.dispose()
        migrate_down(url)


def test_sqlite_embedding_is_json_fallback(tmp_path):
    url = f"sqlite:///{tmp_path / 'j.db'}"
    migrate_up(url)
    engine = make_engine(url)
    cols = {c["name"]: c for c in inspect(engine).get_columns("findings")}
    assert "JSON" in str(cols["embedding"]["type"]).upper()
    engine.dispose()
