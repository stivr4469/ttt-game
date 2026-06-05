"""Add scope_rule table for per-tenant control scoping

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-05

Adds the scope_rule table that lets tenants exclude or include-only
specific control patterns from compliance evaluation.
"""
from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def _table_exists(table: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return table in insp.get_table_names()


def upgrade() -> None:
    if _table_exists("scope_rule"):
        return  # already created by 0000 initial schema on a fresh database

    op.create_table(
        "scope_rule",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("framework_id", sa.String(50), nullable=False),
        sa.Column("control_pattern", sa.String(200), nullable=False),
        sa.Column("action", sa.String(20), nullable=False, server_default="exclude"),
        sa.Column("reason", sa.String(500), nullable=True),
        sa.Column("priority", sa.Integer, nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("conditions", sa.JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_scope_rule_tenant_fw", "scope_rule", ["tenant_id", "framework_id"])
    op.create_index("ix_scope_rule_tenant_id", "scope_rule", ["tenant_id"])

    # Enable RLS on the new table (matches pattern from 0002_rls_sandbox.py)
    bind = op.get_bind()
    bind.execute(sa.text("ALTER TABLE scope_rule ENABLE ROW LEVEL SECURITY"))
    bind.execute(sa.text(
        "CREATE POLICY scope_rule_tenant_isolation ON scope_rule "
        "USING (tenant_id = current_setting('app.tenant_id', true))"
    ))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("DROP POLICY IF EXISTS scope_rule_tenant_isolation ON scope_rule"))
    op.drop_index("ix_scope_rule_tenant_fw", table_name="scope_rule")
    op.drop_index("ix_scope_rule_tenant_id", table_name="scope_rule")
    op.drop_table("scope_rule")
