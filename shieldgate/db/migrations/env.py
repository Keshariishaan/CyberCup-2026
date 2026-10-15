"""
PURPOSE : Alembic environment - uses DATABASE_URL (any SQLAlchemy dialect) and the ORM metadata.
INPUTS  : DATABASE_URL via shieldgate.settings. OUTPUTS : migrations run online/offline.
HOW TO EXTEND : after changing db/models.py run `alembic revision --autogenerate -m "msg"`.
"""
from alembic import context
from sqlalchemy import create_engine

from shieldgate.db.models import Base
from shieldgate.settings import get_settings

target_metadata = Base.metadata
url = get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_offline() if context.is_offline_mode() else run_migrations_online()
