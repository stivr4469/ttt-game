"""Initial schema — create all tables from ORM models

Revision ID: 0000
Revises:
Create Date: 2026-06-05

Creates the full table set via Base.metadata.create_all so that subsequent
delta migrations (0001+) can apply their incremental changes idempotently.
"""
from alembic import op

revision = '0000'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    import models  # noqa: F401 — registers all ORM classes in Base.metadata
    from database import Base
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    import models  # noqa: F401
    from database import Base
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
