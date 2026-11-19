"""Alembic environment for the v2 data layer (SQLite and Postgres)."""

from __future__ import annotations

from alembic import context

from cyberredteam.jobs import tables as _jobs_tables  # noqa: F401  (registers WP7 tables)
from cyberredteam.storage.v2.db import make_engine, resolve_url
from cyberredteam.storage.v2.orm import Base

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    x = context.get_x_argument(as_dictionary=True)
    return x.get("url") or config.get_main_option("sqlalchemy.url") or resolve_url()


def run_migrations_offline() -> None:
    context.configure(
        url=_url(), target_metadata=target_metadata, literal_binds=True, render_as_batch=True
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = config.attributes.get("connection")
    if connectable is not None:
        _run(connectable)
        return
    engine = make_engine(_url())
    try:
        with engine.connect() as connection:
            _run(connection)
    finally:
        engine.dispose()


def _run(connection) -> None:
    context.configure(
        connection=connection, target_metadata=target_metadata, render_as_batch=True
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
