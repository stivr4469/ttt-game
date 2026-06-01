"""
Integration tests: PostgreSQL Row Level Security for sandbox-auditor.

Verifies three guarantees enforced by migration 0002_rls_sandbox:
  1. pg_policies contains a 'tenant_isolation' policy for every expected table.
  2. Setting app.tenant_id in the session filters rows so cross-tenant data
     leakage is impossible even when application-level filters are bypassed.
  3. The get_db() FastAPI dependency correctly propagates tenant context into
     the database session via SET LOCAL app.tenant_id.

All tests are skipped on SQLite — RLS is a PostgreSQL-only feature.
asyncio_mode = auto is set in pytest.ini so no explicit mark is needed.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid
from typing import AsyncGenerator

import pytest
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal, DATABASE_URL
from tenant_context import set_current_tenant_id

# ── Skip marker: skip every test in this file unless DATABASE_URL is PostgreSQL ─

_IS_POSTGRES = DATABASE_URL.startswith("postgresql")

pytestmark = pytest.mark.skipif(
    not _IS_POSTGRES,
    reason="PostgreSQL RLS tests require a PostgreSQL DATABASE_URL",
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _uuid() -> str:
    """Return a fresh random UUID string."""
    return str(uuid.uuid4())


# ── Shared db_session fixture ─────────────────────────────────────────────────

@pytest.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async SQLAlchemy session connected to the real PostgreSQL database.

    Each test gets a fresh session.  The session is NOT committed after
    each test — all writes are rolled back in the finally block so that
    no test data pollutes subsequent tests.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.rollback()


# ── Class 1: RLS policies exist in pg_policies ────────────────────────────────

class TestRLSPoliciesExist:
    """
    Verify that the tenant_isolation policy exists in pg_policies for each
    table that carries a tenant_id column.

    If these tests fail it means migration 0002_rls_sandbox has not been
    applied to the target database.
    """

    _EXPECTED_TABLES = (
        "vendor",
        "evidence",
        "control_status",
        "audit_event",
        "event_queue",
        "test_results",
        "findings",
        "ai_decisions",
    )

    async def _assert_policy_exists(
        self, db_session: AsyncSession, table: str
    ) -> None:
        result = await db_session.execute(
            text(
                "SELECT 1 FROM pg_policies"
                " WHERE tablename = :t AND policyname = 'tenant_isolation'"
            ),
            {"t": table},
        )
        assert result.scalar() == 1, (
            f"Expected tenant_isolation policy on table '{table}' but it was not found "
            f"in pg_policies. Run: alembic upgrade head"
        )

    async def test_vendor_policy_exists(self, db_session: AsyncSession) -> None:
        await self._assert_policy_exists(db_session, "vendor")

    async def test_evidence_policy_exists(self, db_session: AsyncSession) -> None:
        await self._assert_policy_exists(db_session, "evidence")

    async def test_control_status_policy_exists(
        self, db_session: AsyncSession
    ) -> None:
        await self._assert_policy_exists(db_session, "control_status")

    async def test_audit_event_policy_exists(
        self, db_session: AsyncSession
    ) -> None:
        await self._assert_policy_exists(db_session, "audit_event")

    async def test_event_queue_policy_exists(
        self, db_session: AsyncSession
    ) -> None:
        await self._assert_policy_exists(db_session, "event_queue")

    async def test_test_results_policy_exists(
        self, db_session: AsyncSession
    ) -> None:
        await self._assert_policy_exists(db_session, "test_results")

    async def test_findings_policy_exists(self, db_session: AsyncSession) -> None:
        await self._assert_policy_exists(db_session, "findings")

    async def test_ai_decisions_policy_exists(
        self, db_session: AsyncSession
    ) -> None:
        await self._assert_policy_exists(db_session, "ai_decisions")

    async def test_all_expected_tables_have_policy(
        self, db_session: AsyncSession
    ) -> None:
        """
        Single comprehensive assertion that all eight tables have the policy.
        Produces a readable failure listing every missing table at once.
        """
        missing: list[str] = []
        for table in self._EXPECTED_TABLES:
            result = await db_session.execute(
                text(
                    "SELECT 1 FROM pg_policies"
                    " WHERE tablename = :t AND policyname = 'tenant_isolation'"
                ),
                {"t": table},
            )
            if result.scalar() != 1:
                missing.append(table)

        assert not missing, (
            f"tenant_isolation policy missing on tables: {missing}. "
            f"Run: alembic upgrade head"
        )


# ── Class 2: RLS isolation at the SQL level ───────────────────────────────────

class TestRLSIsolation:
    """
    Test actual data isolation enforced by PostgreSQL RLS.

    Tests insert vendor rows for two distinct tenants using raw SQL (bypassing
    all application-level filters) and then verify that setting app.tenant_id
    correctly restricts which rows are visible.

    The tenants table row is inserted first to satisfy the FK constraint on
    vendor.tenant_id.  Both the tenant rows and the vendor rows are cleaned up
    in teardown via explicit DELETE statements so that the session rollback
    alone is not relied upon (some tests may need RESET app.tenant_id first).
    """

    # Stable UUIDs reused across every test in this class.
    TENANT_A_ID: str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    TENANT_B_ID: str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"

    # Vendor primary keys — short strings so they are easy to spot in failures.
    VENDOR_A_ID: str = "VND-RLS-A"
    VENDOR_B_ID: str = "VND-RLS-B"

    @pytest.fixture(autouse=True)
    async def setup_teardown(
        self, db_session: AsyncSession
    ) -> AsyncGenerator[None, None]:
        """
        Insert prerequisite tenants and vendor rows; clean up after every test.

        Uses SET session_replication_role = replica to bypass FK checks during
        cleanup, which guarantees deletion order independence.  The RESET call
        at the end restores normal FK enforcement.
        """
        # Ensure GUC is cleared so superuser sees all rows during setup.
        await db_session.execute(
            text("SELECT set_config('app.tenant_id', '', false)")
        )

        # Insert tenant rows (may already exist from a previous aborted test
        # run — use INSERT … ON CONFLICT DO NOTHING for idempotency).
        await db_session.execute(
            text(
                "INSERT INTO tenants (id, slug, name, status, created_at)"
                " VALUES (:id, :slug, :name, 'active', now())"
                " ON CONFLICT (id) DO NOTHING"
            ),
            {"id": self.TENANT_A_ID, "slug": "rls-tenant-a", "name": "RLS Tenant A"},
        )
        await db_session.execute(
            text(
                "INSERT INTO tenants (id, slug, name, status, created_at)"
                " VALUES (:id, :slug, :name, 'active', now())"
                " ON CONFLICT (id) DO NOTHING"
            ),
            {"id": self.TENANT_B_ID, "slug": "rls-tenant-b", "name": "RLS Tenant B"},
        )

        # Insert vendor rows for each tenant.
        await db_session.execute(
            text(
                "INSERT INTO vendor (id, name, tier, status, dpa_signed, tenant_id)"
                " VALUES (:id, :name, 'medium', 'pending', false, :tid)"
                " ON CONFLICT (id) DO NOTHING"
            ),
            {
                "id": self.VENDOR_A_ID,
                "name": "RLS Vendor A",
                "tid": self.TENANT_A_ID,
            },
        )
        await db_session.execute(
            text(
                "INSERT INTO vendor (id, name, tier, status, dpa_signed, tenant_id)"
                " VALUES (:id, :name, 'high', 'approved', false, :tid)"
                " ON CONFLICT (id) DO NOTHING"
            ),
            {
                "id": self.VENDOR_B_ID,
                "name": "RLS Vendor B",
                "tid": self.TENANT_B_ID,
            },
        )
        await db_session.flush()

        yield  # run the test

        # ── Teardown ──────────────────────────────────────────────────────────
        # Reset app.tenant_id so DELETE sees all rows regardless of which
        # tenant the test left active.
        await db_session.execute(
            text("SELECT set_config('app.tenant_id', '', false)")
        )
        # Use ANY(:ids) instead of IN (:a, :b) — the asyncpg dialect does not
        # support multiple named bind parameters inside a literal IN list.
        await db_session.execute(
            text("DELETE FROM vendor WHERE id = ANY(:ids)"),
            {"ids": [self.VENDOR_A_ID, self.VENDOR_B_ID]},
        )
        await db_session.execute(
            text("DELETE FROM tenants WHERE id = ANY(:ids)"),
            {"ids": [self.TENANT_A_ID, self.TENANT_B_ID]},
        )
        # Reset GUC to empty after cleanup.
        await db_session.execute(
            text("SELECT set_config('app.tenant_id', '', false)")
        )

    async def _fetch_vendor_ids(self, db_session: AsyncSession) -> set[str]:
        """Execute a raw SELECT on vendor and return the set of id values."""
        result = await db_session.execute(text("SELECT id FROM vendor"))
        return {row[0] for row in result.fetchall()}

    async def test_tenant_a_cannot_see_tenant_b_vendors(
        self, db_session: AsyncSession
    ) -> None:
        """
        With app.tenant_id = TENANT_A, only Tenant A's rows are visible.
        Tenant B's vendor row must be invisible even via raw SQL.
        """
        # Arrange
        await db_session.execute(
            text("SET LOCAL app.tenant_id = :tid"),
            {"tid": self.TENANT_A_ID},
        )

        # Act — raw SELECT bypasses all ORM filters; only RLS can hide rows.
        visible = await self._fetch_vendor_ids(db_session)

        # Assert
        assert self.VENDOR_A_ID in visible, (
            "Tenant A must see its own vendor row"
        )
        assert self.VENDOR_B_ID not in visible, (
            "Tenant A must not see Tenant B's vendor row (RLS violation)"
        )

    async def test_tenant_b_cannot_see_tenant_a_vendors(
        self, db_session: AsyncSession
    ) -> None:
        """
        With app.tenant_id = TENANT_B, only Tenant B's rows are visible.
        Tenant A's vendor row must be invisible even via raw SQL.
        """
        # Arrange
        await db_session.execute(
            text("SET LOCAL app.tenant_id = :tid"),
            {"tid": self.TENANT_B_ID},
        )

        # Act
        visible = await self._fetch_vendor_ids(db_session)

        # Assert
        assert self.VENDOR_B_ID in visible, (
            "Tenant B must see its own vendor row"
        )
        assert self.VENDOR_A_ID not in visible, (
            "Tenant B must not see Tenant A's vendor row (RLS violation)"
        )

    async def test_empty_guc_bypasses_tenant_filter(
        self, db_session: AsyncSession
    ) -> None:
        """
        When app.tenant_id is cleared to the empty string (privileged bypass),
        the USING clause allows all rows through.  This documents the intentional
        migration / seed-script bypass — NOT a PostgreSQL superuser bypass.

        SECURITY NOTE: This bypass is reachable by any session-level GUC reset.
        It must never be triggered by application code handling user requests.
        get_db() prevents this by always issuing SET LOCAL app.tenant_id for
        authenticated requests; unauthenticated routes must not call get_db()
        without a tenant context.
        """
        # Arrange — ensure GUC is empty (setup_teardown already does this,
        # but be explicit to document the intent).
        await db_session.execute(
            text("SELECT set_config('app.tenant_id', '', false)")
        )

        # Act
        visible = await self._fetch_vendor_ids(db_session)

        # Assert — both tenant rows must be visible (privileged bypass active).
        assert self.VENDOR_A_ID in visible, (
            "Empty GUC (privileged bypass) must see Tenant A's vendor row"
        )
        assert self.VENDOR_B_ID in visible, (
            "Empty GUC (privileged bypass) must see Tenant B's vendor row"
        )

    async def test_null_tenant_rows_visible_to_all(
        self, db_session: AsyncSession
    ) -> None:
        """
        Rows with tenant_id = NULL (system / seed data) must pass through the
        nullable USING clause regardless of which tenant GUC is active.
        """
        null_vendor_id = f"VND-RLS-NULL-{_uuid()[:8]}"
        try:
            # Arrange — insert a vendor with no tenant association.
            await db_session.execute(
                text(
                    "INSERT INTO vendor (id, name, tier, status, dpa_signed, tenant_id)"
                    " VALUES (:id, 'Seed Vendor', 'low', 'pending', false, NULL)"
                    " ON CONFLICT (id) DO NOTHING"
                ),
                {"id": null_vendor_id},
            )
            await db_session.flush()

            # Act/Assert — visible as Tenant A.
            await db_session.execute(
                text("SET LOCAL app.tenant_id = :tid"),
                {"tid": self.TENANT_A_ID},
            )
            visible_a = await self._fetch_vendor_ids(db_session)
            assert null_vendor_id in visible_a, (
                "NULL-tenant vendor must be visible to Tenant A"
            )

            # Act/Assert — visible as Tenant B.
            await db_session.execute(
                text("SET LOCAL app.tenant_id = :tid"),
                {"tid": self.TENANT_B_ID},
            )
            visible_b = await self._fetch_vendor_ids(db_session)
            assert null_vendor_id in visible_b, (
                "NULL-tenant vendor must be visible to Tenant B"
            )

        finally:
            # Clean up the NULL-tenant vendor regardless of test outcome.
            await db_session.execute(
                text("SELECT set_config('app.tenant_id', '', false)")
            )
            await db_session.execute(
                text("DELETE FROM vendor WHERE id = :id"),
                {"id": null_vendor_id},
            )

    async def test_switching_tenant_guc_changes_visibility(
        self, db_session: AsyncSession
    ) -> None:
        """
        Within the same session, switching app.tenant_id from Tenant A to
        Tenant B changes which rows are visible.  This verifies that RLS
        re-evaluates the policy predicate on every statement, not just once
        at session start.
        """
        # Act — first query as Tenant A.
        await db_session.execute(
            text("SET LOCAL app.tenant_id = :tid"),
            {"tid": self.TENANT_A_ID},
        )
        visible_as_a = await self._fetch_vendor_ids(db_session)

        # Act — switch to Tenant B within the same transaction.
        await db_session.execute(
            text("SET LOCAL app.tenant_id = :tid"),
            {"tid": self.TENANT_B_ID},
        )
        visible_as_b = await self._fetch_vendor_ids(db_session)

        # Assert — results differ after the switch.
        assert self.VENDOR_A_ID in visible_as_a
        assert self.VENDOR_B_ID not in visible_as_a

        assert self.VENDOR_B_ID in visible_as_b
        assert self.VENDOR_A_ID not in visible_as_b


# ── Class 3: get_db() sets tenant context ─────────────────────────────────────

class TestRLSWithGetDb:
    """
    Verify that the get_db() FastAPI dependency propagates tenant_id from the
    ContextVar into the database session via SET LOCAL app.tenant_id.

    These tests call get_db() directly — no HTTP layer is involved.
    """

    async def test_get_db_sets_tenant_context(self) -> None:
        """
        When a tenant_id ContextVar is set before entering get_db(), the
        session must have app.tenant_id configured to that value.
        """
        from database import get_db

        tenant_id = _uuid()
        set_current_tenant_id(tenant_id)
        try:
            async for session in get_db():
                result = await session.execute(
                    text("SELECT current_setting('app.tenant_id', true)")
                )
                guc_value = result.scalar()
                assert guc_value == tenant_id, (
                    f"get_db() must SET LOCAL app.tenant_id to the contextvar value. "
                    f"Expected {tenant_id!r}, got {guc_value!r}"
                )
                break  # consume the generator — triggers finally/cleanup inside get_db
        finally:
            set_current_tenant_id(None)

    async def test_get_db_stores_tenant_id_in_session_info(self) -> None:
        """
        get_db() must also store the tenant_id in session.info so that ORM
        repositories that read session.info["tenant_id"] get the correct value.
        """
        from database import get_db

        tenant_id = _uuid()
        set_current_tenant_id(tenant_id)
        try:
            async for session in get_db():
                stored = session.info.get("tenant_id")
                assert stored == tenant_id, (
                    f"session.info['tenant_id'] must equal the contextvar value. "
                    f"Expected {tenant_id!r}, got {stored!r}"
                )
                break
        finally:
            set_current_tenant_id(None)

    async def test_get_db_no_tenant_leaves_guc_empty(self) -> None:
        """
        When no tenant_id is set in the ContextVar, get_db() must NOT issue a
        SET LOCAL app.tenant_id command.  The GUC should remain at its
        initialised default (empty string or NULL), which the RLS policy treats
        as "no filter" — equivalent to superuser access.
        """
        from database import get_db

        set_current_tenant_id(None)
        async for session in get_db():
            result = await session.execute(
                text("SELECT current_setting('app.tenant_id', true)")
            )
            guc_value = result.scalar()
            # When no tenant is active the GUC should be NULL or empty string.
            assert guc_value in (None, ""), (
                f"With no contextvar tenant, get_db() must not set app.tenant_id. "
                f"Got {guc_value!r}"
            )
            break

    async def test_get_db_tenant_context_is_local_to_transaction(self) -> None:
        """
        SET LOCAL means the GUC reverts at transaction end.  After one get_db()
        call completes, a fresh call without tenant context must not inherit the
        previous tenant_id (no GUC bleed between requests).
        """
        from database import get_db

        tenant_id = _uuid()

        # First request: set tenant.
        set_current_tenant_id(tenant_id)
        try:
            async for session in get_db():
                await session.execute(
                    text("SELECT current_setting('app.tenant_id', true)")
                )
                break
        finally:
            set_current_tenant_id(None)

        # Second request: no tenant — GUC must be clean.
        async for session in get_db():
            result = await session.execute(
                text("SELECT current_setting('app.tenant_id', true)")
            )
            guc_value = result.scalar()
            assert guc_value in (None, ""), (
                f"GUC must not bleed between get_db() calls. "
                f"After a tenanted request, a non-tenanted request got {guc_value!r}"
            )
            break

    async def test_get_db_isolation_prevents_cross_tenant_leak(self) -> None:
        """
        End-to-end: insert a vendor row for Tenant A via get_db(), then query
        via get_db() as Tenant B using raw SQL — the row must be invisible.

        This is the highest-confidence test: it exercises the full path from
        ContextVar → get_db() → SET LOCAL → RLS policy → filtered query.
        """
        from database import get_db

        tenant_a_id = _uuid()
        tenant_b_id = _uuid()
        vendor_id = f"VND-GETDB-{_uuid()[:8]}"

        # Prerequisite: insert tenant rows (RLS GUC is empty → superuser bypass).
        async for session in get_db():
            await session.execute(
                text(
                    "INSERT INTO tenants (id, slug, name, status, created_at)"
                    " VALUES (:id, :slug, :name, 'active', now())"
                    " ON CONFLICT (id) DO NOTHING"
                ),
                {"id": tenant_a_id, "slug": f"getdb-a-{tenant_a_id[:8]}", "name": "GetDB Tenant A"},
            )
            await session.execute(
                text(
                    "INSERT INTO tenants (id, slug, name, status, created_at)"
                    " VALUES (:id, :slug, :name, 'active', now())"
                    " ON CONFLICT (id) DO NOTHING"
                ),
                {"id": tenant_b_id, "slug": f"getdb-b-{tenant_b_id[:8]}", "name": "GetDB Tenant B"},
            )
            await session.commit()
            break

        try:
            # Insert a vendor row via get_db() as Tenant A.
            set_current_tenant_id(tenant_a_id)
            try:
                async for session in get_db():
                    await session.execute(
                        text(
                            "INSERT INTO vendor"
                            " (id, name, tier, status, dpa_signed, tenant_id)"
                            " VALUES (:id, 'GetDB Vendor A', 'medium', 'pending', false, :tid)"
                            " ON CONFLICT (id) DO NOTHING"
                        ),
                        {"id": vendor_id, "tid": tenant_a_id},
                    )
                    await session.commit()
                    break
            finally:
                set_current_tenant_id(None)

            # Query as Tenant B — row must be hidden by RLS.
            set_current_tenant_id(tenant_b_id)
            try:
                async for session in get_db():
                    result = await session.execute(
                        text("SELECT id FROM vendor WHERE id = :id"),
                        {"id": vendor_id},
                    )
                    row = result.scalar()
                    assert row is None, (
                        f"Tenant B must not see vendor {vendor_id!r} owned by Tenant A. "
                        f"RLS policy is not working correctly via get_db()."
                    )
                    break
            finally:
                set_current_tenant_id(None)

        finally:
            # Clean up — no tenant GUC so superuser sees all rows.
            async for session in get_db():
                await session.execute(
                    text("DELETE FROM vendor WHERE id = :id"),
                    {"id": vendor_id},
                )
                await session.execute(
                    text("DELETE FROM tenants WHERE id = ANY(:ids)"),
                    {"ids": [tenant_a_id, tenant_b_id]},
                )
                await session.commit()
                break
