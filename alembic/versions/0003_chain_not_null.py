"""Backfill and enforce NOT NULL on evidence chain columns

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-01

Chain columns were added as nullable in 0001. This migration:
  1. Backfills sha256_hash and previous_hash with empty string where NULL.
  2. Sets both columns NOT NULL (chain_valid already NOT NULL from 0001).

PostgreSQL uses ALTER COLUMN; SQLite uses batch_alter_table.
"""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def _col_exists(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return column in [c["name"] for c in insp.get_columns(table)]


def upgrade() -> None:
    bind = op.get_bind()

    # ── 1. Backfill NULLs with empty string ─────────────────────────────────
    if _col_exists("evidence", "sha256_hash"):
        bind.execute(sa.text(
            "UPDATE evidence SET sha256_hash = '' WHERE sha256_hash IS NULL"
        ))
    if _col_exists("evidence", "previous_hash"):
        bind.execute(sa.text(
            "UPDATE evidence SET previous_hash = '' WHERE previous_hash IS NULL"
        ))

    # ── 2. Set NOT NULL ──────────────────────────────────────────────────────
    with op.batch_alter_table("evidence") as batch_op:
        if _col_exists("evidence", "sha256_hash"):
            batch_op.alter_column(
                "sha256_hash",
                existing_type=sa.String(64),
                nullable=False,
                server_default=None,
            )
        if _col_exists("evidence", "previous_hash"):
            batch_op.alter_column(
                "previous_hash",
                existing_type=sa.String(64),
                nullable=False,
                server_default="",
            )


def downgrade() -> None:
    with op.batch_alter_table("evidence") as batch_op:
        if _col_exists("evidence", "previous_hash"):
            batch_op.alter_column(
                "previous_hash",
                existing_type=sa.String(64),
                nullable=True,
                server_default="",
            )
        if _col_exists("evidence", "sha256_hash"):
            batch_op.alter_column(
                "sha256_hash",
                existing_type=sa.String(64),
                nullable=True,
                server_default=None,
            )
