"""Enable Row Level Security on all tenant-scoped tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-01 00:00:00.000000

Enables PostgreSQL RLS with a tenant_isolation policy on every table that
carries a tenant_id column.  The tenants table itself is intentionally
excluded — it is the root identity table and has no tenant_id column.

Tables with nullable tenant_id get a permissive USING clause that also
allows NULL tenant_id rows through (useful for seed / system-owned rows).
Tables with a non-nullable tenant_id (tenant_secrets, tenant_users) use a
stricter clause that never lets NULL through.

IMPORTANT — app role setup (run once as superuser before applying migrations):
    CREATE ROLE app_user WITH LOGIN PASSWORD '...';
    GRANT CONNECT ON DATABASE compliance TO app_user;
    GRANT USAGE ON SCHEMA public TO app_user;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
    -- Note: app_user does NOT have BYPASSRLS — RLS policies apply to all its queries.
"""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None

# Tables where tenant_id is nullable=True.
# Policy allows NULL tenant_id through (system / seed rows).
_NULLABLE_TENANT_TABLES = (
    "control",
    "evidence",
    "control_status",
    "risk_entry",
    "vendor",
    "policy_draft",
    "training_completion",
    "audit_event",
    "remediation_ticket",
    "event_queue",
    "remediation",
    "custom_control",
    "policy_version",
    "policy_signature",
    "vendor_record",
    "mdm_device",
    "hr_employee",
    "asset_record",
    "auditor_comment",
    "access_review_decision",
    "vulnerability_record",
    "training_completion_detail",
    "pentest_report",
    "questionnaire_response",
    "test_definitions",
    "test_control_mappings",
    "test_runs",
    "test_results",
    "audit_logs",
    "findings",
    "ai_decisions",
    "trust_access_requests",
)

# Tables where tenant_id is NOT NULL — stricter policy, no NULL passthrough.
_NONNULL_TENANT_TABLES = (
    "tenant_secrets",
    "tenant_users",
)

_ALL_TABLES = _NULLABLE_TENANT_TABLES + _NONNULL_TENANT_TABLES

_POLICY_NAME = "tenant_isolation"

# USING clause for tables where tenant_id may be NULL (nullable column).
# Rows pass when:
#   - the GUC is not set at all (IS NULL result from missing param) — PRIVILEGED BYPASS
#   - the GUC is set to empty string (the initialised default)     — PRIVILEGED BYPASS
#   - the row itself has no tenant_id (system / seed data)
#   - the row's tenant_id matches the session GUC
#
# SECURITY INVARIANT: The first two branches (NULL / empty-string GUC) are
# intentional privileged bypasses used by migrations, seed scripts, and
# background workers that operate across all tenants.  They must NEVER be
# reachable by a normal application session that handles user requests:
#   - get_db() issues SET LOCAL app.tenant_id = <id> for every authenticated
#     request, which overrides the empty-string session default for that
#     transaction.
#   - app_user must NOT have BYPASSRLS.
#   - Unauthenticated / public API routes must never call get_db() without
#     first setting the tenant ContextVar, or they will see all tenant rows.
_NULLABLE_USING = """\
    current_setting('app.tenant_id', true) IS NULL
    OR current_setting('app.tenant_id', true) = ''
    OR tenant_id IS NULL
    OR tenant_id::text = current_setting('app.tenant_id', true)\
"""

# USING clause for tables where tenant_id is always present.
# Rows pass only when the GUC is unset/empty (PRIVILEGED BYPASS) OR matches exactly.
# See the security invariant note above — the empty-string bypass applies here too.
_NONNULL_USING = """\
    current_setting('app.tenant_id', true) IS NULL
    OR current_setting('app.tenant_id', true) = ''
    OR tenant_id::text = current_setting('app.tenant_id', true)\
"""


def _policy_exists(conn, table: str) -> bool:
    """Return True if the tenant_isolation policy already exists on *table*."""
    result = conn.execute(
        sa.text(
            "SELECT 1 FROM pg_policies"
            " WHERE tablename = :t AND policyname = :p"
        ),
        {"t": table, "p": _POLICY_NAME},
    )
    return result.scalar() is not None


def upgrade() -> None:
    conn = op.get_bind()

    if conn.dialect.name != "postgresql":
        return

    # Initialise the custom GUC in the current session so that
    # current_setting('app.tenant_id', true) never raises
    # "unrecognised configuration parameter" when first called.
    # The empty-string default means "no tenant filter active".
    conn.execute(sa.text("SELECT set_config('app.tenant_id', '', false)"))

    # Tables with nullable tenant_id — NULL rows are allowed through.
    for table in _NULLABLE_TENANT_TABLES:
        # Always ensure RLS is enabled — even if the policy already exists, RLS
        # may have been disabled manually.  ALTER TABLE ... ENABLE ROW LEVEL
        # SECURITY is idempotent (no error if already enabled).
        conn.execute(
            sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        )
        if not _policy_exists(conn, table):
            conn.execute(
                sa.text(
                    f"CREATE POLICY {_POLICY_NAME} ON {table}"
                    f" USING ({_NULLABLE_USING})"
                )
            )

    # Tables with non-nullable tenant_id — stricter, no NULL passthrough.
    for table in _NONNULL_TENANT_TABLES:
        conn.execute(
            sa.text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        )
        if not _policy_exists(conn, table):
            conn.execute(
                sa.text(
                    f"CREATE POLICY {_POLICY_NAME} ON {table}"
                    f" USING ({_NONNULL_USING})"
                )
            )


def downgrade() -> None:
    conn = op.get_bind()

    if conn.dialect.name != "postgresql":
        return

    for table in _ALL_TABLES:
        conn.execute(
            sa.text(
                f"DROP POLICY IF EXISTS {_POLICY_NAME} ON {table}"
            )
        )
        conn.execute(
            sa.text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        )
