"""Add evidence hash-chain columns

Revision ID: 0001
Revises:
Create Date: 2026-06-01 00:00:00.000000

Adds sha256_hash, previous_hash, and chain_valid to the evidence table.
Replaces the hand-rolled _migrate_evidence_chain_columns() runtime migration.
"""
from alembic import op
import sqlalchemy as sa

revision = '0001'
down_revision = '0000'
branch_labels = None
depends_on = None


def _col_exists(table: str, column: str) -> bool:
    """Check whether a column already exists (handles pre-migration databases)."""
    bind = op.get_bind()
    insp = sa.inspect(bind)
    cols = [c["name"] for c in insp.get_columns(table)]
    return column in cols


def upgrade() -> None:
    with op.batch_alter_table("evidence") as batch_op:
        if not _col_exists("evidence", "sha256_hash"):
            batch_op.add_column(sa.Column("sha256_hash", sa.String(64), nullable=True))
        if not _col_exists("evidence", "previous_hash"):
            batch_op.add_column(sa.Column("previous_hash", sa.String(64), nullable=True))
        if not _col_exists("evidence", "chain_valid"):
            batch_op.add_column(
                sa.Column("chain_valid", sa.Boolean(), nullable=False, server_default=sa.true())
            )


def downgrade() -> None:
    with op.batch_alter_table("evidence") as batch_op:
        if _col_exists("evidence", "chain_valid"):
            batch_op.drop_column("chain_valid")
        if _col_exists("evidence", "previous_hash"):
            batch_op.drop_column("previous_hash")
        if _col_exists("evidence", "sha256_hash"):
            batch_op.drop_column("sha256_hash")
