"""
PURPOSE : Initial schema (users, privileges, documents, conversations, messages, token usage,
          audit log, approvals, config versions).
INPUTS  : the ORM metadata at the time of this revision. OUTPUTS : all tables.
HOW TO EXTEND : add new revisions with `alembic revision --autogenerate`; do not edit this one.
"""
from alembic import op

from shieldgate.db.models import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
