"""Run DB migrations at container start: Alembic head, then the procrastinate schema.

``python -m cyberredteam.jobs.migrate`` (idempotent). Used by the API container.
"""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from cyberredteam.storage.v2.db import make_engine, resolve_url

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[3]  # the project dir holding alembic.ini


def alembic_upgrade(url: str | None = None) -> None:
    url = resolve_url(url)
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(cfg, "head")


def apply_procrastinate_schema(url: str | None = None) -> bool:
    """Create procrastinate's tables on Postgres if missing. Returns True if applied."""
    from cyberredteam.jobs.queue import make_app, make_connector

    url = resolve_url(url)
    connector = make_connector(url)
    if connector is None:
        return False
    engine = make_engine(url)
    try:
        if "procrastinate_jobs" in inspect(engine).get_table_names():
            return False
    finally:
        engine.dispose()
    app = make_app(connector)
    with app.open():
        app.schema_manager.apply_schema()
    return True


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    alembic_upgrade()
    applied = apply_procrastinate_schema()
    logger.info("migrations at head; procrastinate schema applied=%s", applied)


if __name__ == "__main__":
    main()
