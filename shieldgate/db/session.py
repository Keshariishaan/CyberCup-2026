"""
PURPOSE : Engine/session factory driven by DATABASE_URL (no dialect-specific SQL).
INPUTS  : database URL string.
OUTPUTS : make_engine(), make_session_factory(), init_db(), session_scope().
HOW TO EXTEND : point DATABASE_URL at PostgreSQL (postgresql+psycopg://...).
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from shieldgate.db.models import Base


def make_engine(url: str) -> Engine:
    """Create an engine; in-memory SQLite uses a shared static pool."""
    if url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url or url.endswith("sqlite://"):
            kwargs["poolclass"] = StaticPool
        engine = create_engine(url, **kwargs)

        @event.listens_for(engine, "connect")
        def _fk(dbapi_conn, _):  # noqa: ANN001
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
        return engine
    return create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=20)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def ensure_columns(engine: Engine) -> list[str]:
    """Add columns that exist in the models but not yet in the database (lightweight auto-upgrade).

    create_all() only creates missing TABLES, so an older database file would otherwise break when a model gains
    a column. New columns are added as nullable; code treats NULL as the default. Production: use Alembic.
    """
    added: list[str] = []
    insp = inspect(engine)
    with engine.begin() as cn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name not in have:
                    ddl = col.type.compile(dialect=engine.dialect)
                    cn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl}'))
                    added.append(f"{table.name}.{col.name}")
    return added


def init_db(engine: Engine) -> None:
    """Create tables and upgrade older ones (dev convenience; production should run `alembic upgrade head`)."""
    Base.metadata.create_all(engine)
    ensure_columns(engine)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional scope: commit on success, rollback on error."""
    s = factory()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
