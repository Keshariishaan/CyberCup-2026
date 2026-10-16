"""
PURPOSE : Schema for the second bulk update: user attributes (department, region, clearance), document version /
          attributes / chunk rules, incidents, reveal requests, access requests and policy tests stored with
          config versions. Idempotent: creates missing tables and adds missing columns.
INPUTS  : the ORM metadata. OUTPUTS : upgraded schema.
HOW TO EXTEND : add a new revision per schema change; do not edit this one.
"""
from alembic import op
from sqlalchemy import inspect, text

from shieldgate.db.models import Base

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)  # new tables
    insp = inspect(bind)
    for table in Base.metadata.sorted_tables:  # new columns on existing tables
        have = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in have:
                ddl = col.type.compile(dialect=bind.dialect)
                bind.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl}'))


def downgrade() -> None:
    pass  # additive migration; nothing is removed
