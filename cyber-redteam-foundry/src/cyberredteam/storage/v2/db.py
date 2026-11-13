"""Engine and session factory for the v2 data layer."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from cyberredteam.settings import get_settings

DEFAULT_SQLITE_URL = "sqlite:///runs/canary_v2.db"


def resolve_url(url: str | None = None) -> str:
    return url or get_settings().database_url or DEFAULT_SQLITE_URL


def make_engine(url: str | None = None) -> Engine:
    """Create an engine. SQLite gets foreign keys switched on; Postgres uses psycopg."""
    url = resolve_url(url)
    # hide_parameters: SQLAlchemy errors must never echo bound (evidence) values.
    kwargs: dict = {"hide_parameters": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
        else:
            path = url.split("///", 1)[-1]
            if path:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
    else:
        kwargs["pool_pre_ping"] = True
    engine = create_engine(url, **kwargs)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


def make_session_factory(engine: Engine | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=engine or make_engine(), expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """One transaction: commit on success, roll back on error."""
    session = factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
