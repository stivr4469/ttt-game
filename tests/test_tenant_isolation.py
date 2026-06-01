"""
Integration tests for multi-tenant isolation in sandbox-auditor.

Verifies that repository-layer queries are correctly scoped by tenant_id:
  - VendorRepository.list() must not leak records across tenants.
  - EventQueueRepository.get_pending() must not leak records across tenants.
  - A session set to tenant A never sees tenant B's data, and vice versa.

All tests use an in-memory SQLite database — no server, no HTTP.
asyncio_mode = auto is configured in pytest.ini so no explicit mark needed.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid
from typing import AsyncGenerator

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from database import Base
from db_repository import EventQueueRepository, VendorRepository
from tenant_context import set_current_tenant_id

# ── Constants ─────────────────────────────────────────────────────────────────

TENANT_A = "00000000-0000-0000-0000-000000000001"
TENANT_B = "00000000-0000-0000-0000-000000000002"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_session(factory: async_sessionmaker, tenant_id: str) -> AsyncSession:
    """Create a fresh session with tenant_id set in session.info."""
    session = factory()
    session.info["tenant_id"] = tenant_id
    return session


def _uid() -> str:
    return str(uuid.uuid4())


# ── Shared engine fixture (one per test module invocation) ───────────────────

@pytest.fixture
async def db_factory() -> AsyncGenerator[async_sessionmaker, None]:
    """
    In-memory SQLite engine shared within a single test.
    Creates the full schema, yields a session factory, then disposes.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


# ── VendorRepository isolation tests ─────────────────────────────────────────

class TestVendorIsolation:
    """VendorRepository.list() must respect tenant_id boundaries."""

    async def test_tenant_a_cannot_see_tenant_b_vendors(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Vendors created for tenant B are invisible when querying as tenant A.
        """
        # Arrange — insert two vendors for tenant B
        async with _make_session(db_factory, TENANT_B) as session_b:
            repo_b = VendorRepository(session_b)
            await repo_b.create(
                vendor_id="VND-B-001",
                name="Tenant B Vendor Alpha",
                tier="critical",
                status="approved",
            )
            await repo_b.create(
                vendor_id="VND-B-002",
                name="Tenant B Vendor Beta",
                tier="medium",
                status="pending",
            )
            await session_b.commit()

        # Act — query as tenant A
        async with _make_session(db_factory, TENANT_A) as session_a:
            repo_a = VendorRepository(session_a)
            vendors_a = await repo_a.list()

        # Assert — tenant A sees none of tenant B's vendors
        vendor_ids = {v.id for v in vendors_a}
        assert "VND-B-001" not in vendor_ids, (
            "Tenant A must not see VND-B-001 belonging to tenant B"
        )
        assert "VND-B-002" not in vendor_ids, (
            "Tenant A must not see VND-B-002 belonging to tenant B"
        )

    async def test_tenant_b_cannot_see_tenant_a_vendors(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Vendors created for tenant A are invisible when querying as tenant B.
        """
        # Arrange — insert a vendor for tenant A
        async with _make_session(db_factory, TENANT_A) as session_a:
            repo_a = VendorRepository(session_a)
            await repo_a.create(
                vendor_id="VND-A-001",
                name="Tenant A Vendor",
                tier="high",
                status="pending",
            )
            await session_a.commit()

        # Act — query as tenant B
        async with _make_session(db_factory, TENANT_B) as session_b:
            repo_b = VendorRepository(session_b)
            vendors_b = await repo_b.list()

        # Assert — tenant B sees none of tenant A's vendors
        vendor_ids = {v.id for v in vendors_b}
        assert "VND-A-001" not in vendor_ids, (
            "Tenant B must not see VND-A-001 belonging to tenant A"
        )

    async def test_each_tenant_sees_only_own_vendors(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Tenants A and B each see exactly their own vendors and nothing else.
        """
        # Arrange — populate both tenants
        async with _make_session(db_factory, TENANT_A) as session_a:
            repo_a = VendorRepository(session_a)
            await repo_a.create("VND-A-10", "Alpha A", tier="critical", status="approved")
            await repo_a.create("VND-A-11", "Bravo A", tier="medium", status="pending")
            await session_a.commit()

        async with _make_session(db_factory, TENANT_B) as session_b:
            repo_b = VendorRepository(session_b)
            await repo_b.create("VND-B-10", "Alpha B", tier="high", status="approved")
            await session_b.commit()

        # Act
        async with _make_session(db_factory, TENANT_A) as session_a:
            results_a = await VendorRepository(session_a).list()

        async with _make_session(db_factory, TENANT_B) as session_b:
            results_b = await VendorRepository(session_b).list()

        ids_a = {v.id for v in results_a}
        ids_b = {v.id for v in results_b}

        # Assert — A sees its two records
        assert "VND-A-10" in ids_a
        assert "VND-A-11" in ids_a
        assert "VND-B-10" not in ids_a

        # Assert — B sees its one record only
        assert "VND-B-10" in ids_b
        assert "VND-A-10" not in ids_b
        assert "VND-A-11" not in ids_b

    async def test_vendor_list_filter_by_status_is_still_tenant_scoped(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Filtering by status in list() must not widen the tenant boundary.
        Tenant A querying status='approved' must not return tenant B's approved vendors.
        """
        # Arrange
        async with _make_session(db_factory, TENANT_B) as session_b:
            await VendorRepository(session_b).create(
                "VND-B-APPR", "B Approved Vendor", tier="critical", status="approved"
            )
            await session_b.commit()

        # Act — tenant A queries approved vendors
        async with _make_session(db_factory, TENANT_A) as session_a:
            results = await VendorRepository(session_a).list(status="approved")

        ids = {v.id for v in results}
        assert "VND-B-APPR" not in ids, (
            "Filtering by status must not bypass tenant isolation"
        )


# ── EventQueueRepository isolation tests ─────────────────────────────────────

class TestEventQueueIsolation:
    """EventQueueRepository.get_pending() must respect tenant_id boundaries."""

    async def test_tenant_a_cannot_see_tenant_b_pending_events(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Pending events enqueued by tenant B are invisible to tenant A's poller.
        """
        # Arrange — enqueue an event as tenant B
        async with _make_session(db_factory, TENANT_B) as session_b:
            repo_b = EventQueueRepository(session_b)
            await repo_b.enqueue(
                event_id="evt-b-0001",
                event_type="vendor.risk_scored",
                payload='{"vendor_id": "VND-B-001"}',
                entity_id="VND-B-001",
            )
            await session_b.commit()

        # Act — poll pending events as tenant A
        async with _make_session(db_factory, TENANT_A) as session_a:
            pending_a = await EventQueueRepository(session_a).get_pending()

        # Assert
        event_ids = {e.id for e in pending_a}
        assert "evt-b-0001" not in event_ids, (
            "Tenant A must not receive pending events belonging to tenant B"
        )

    async def test_tenant_b_cannot_see_tenant_a_pending_events(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Pending events enqueued by tenant A are invisible to tenant B's poller.
        """
        # Arrange
        async with _make_session(db_factory, TENANT_A) as session_a:
            repo_a = EventQueueRepository(session_a)
            await repo_a.enqueue(
                event_id="evt-a-0001",
                event_type="evidence.created",
                payload='{"control_id": "CC6.1"}',
                entity_id="CC6.1",
            )
            await session_a.commit()

        # Act
        async with _make_session(db_factory, TENANT_B) as session_b:
            pending_b = await EventQueueRepository(session_b).get_pending()

        # Assert
        event_ids = {e.id for e in pending_b}
        assert "evt-a-0001" not in event_ids, (
            "Tenant B must not receive pending events belonging to tenant A"
        )

    async def test_each_tenant_polls_only_own_events(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Each tenant's poller returns exactly its own pending events.
        Events from the other tenant are never included.
        """
        # Arrange — both tenants enqueue events
        async with _make_session(db_factory, TENANT_A) as session_a:
            repo_a = EventQueueRepository(session_a)
            await repo_a.enqueue("evt-a-100", "control.updated", '{}', "CC6.1")
            await repo_a.enqueue("evt-a-101", "risk.created", '{}', "RISK-001")
            await session_a.commit()

        async with _make_session(db_factory, TENANT_B) as session_b:
            repo_b = EventQueueRepository(session_b)
            await repo_b.enqueue("evt-b-100", "vendor.approved", '{}', "VND-B-001")
            await session_b.commit()

        # Act
        async with _make_session(db_factory, TENANT_A) as session_a:
            pending_a = await EventQueueRepository(session_a).get_pending()

        async with _make_session(db_factory, TENANT_B) as session_b:
            pending_b = await EventQueueRepository(session_b).get_pending()

        ids_a = {e.id for e in pending_a}
        ids_b = {e.id for e in pending_b}

        # A sees its own two events
        assert "evt-a-100" in ids_a
        assert "evt-a-101" in ids_a
        assert "evt-b-100" not in ids_a

        # B sees its own one event only
        assert "evt-b-100" in ids_b
        assert "evt-a-100" not in ids_b
        assert "evt-a-101" not in ids_b

    async def test_marking_done_does_not_affect_other_tenant(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Marking an event as done within one tenant session does not
        affect the pending count of the other tenant.
        """
        # Arrange
        async with _make_session(db_factory, TENANT_A) as session_a:
            await EventQueueRepository(session_a).enqueue(
                "evt-a-200", "evidence.created", '{}', "CC7.1"
            )
            await session_a.commit()

        async with _make_session(db_factory, TENANT_B) as session_b:
            await EventQueueRepository(session_b).enqueue(
                "evt-b-200", "evidence.created", '{}', "CC7.1"
            )
            await session_b.commit()

        # Act — tenant A marks its event done
        async with _make_session(db_factory, TENANT_A) as session_a:
            await EventQueueRepository(session_a).mark_done("evt-a-200")
            await session_a.commit()

        # Assert — tenant B's event is untouched and still pending
        async with _make_session(db_factory, TENANT_B) as session_b:
            pending_b = await EventQueueRepository(session_b).get_pending()

        ids_b = {e.id for e in pending_b}
        assert "evt-b-200" in ids_b, (
            "Tenant B's event must still be pending after tenant A marked its own done"
        )


# ── contextvar integration: set_current_tenant_id ────────────────────────────

class TestContextVarTenantIsolation:
    """
    Verify that set_current_tenant_id() + manual session.info assignment
    produces the same tenant-scoped behaviour used by get_db() in production.
    """

    async def test_set_current_tenant_id_scopes_vendor_query(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        When set_current_tenant_id() is called before creating a session,
        manually propagating it to session.info must scope the query correctly.
        """
        # Populate tenant B
        async with _make_session(db_factory, TENANT_B) as session_b:
            await VendorRepository(session_b).create(
                "VND-CTX-B", "Ctx Vendor B", tier="medium", status="pending"
            )
            await session_b.commit()

        # Simulate what get_db() does: set contextvar, then read it into session.info
        set_current_tenant_id(TENANT_A)
        try:
            async with db_factory() as session:
                from tenant_context import get_current_tenant_id
                tid = get_current_tenant_id()
                assert tid == TENANT_A
                session.info["tenant_id"] = tid

                results = await VendorRepository(session).list()
        finally:
            set_current_tenant_id(None)  # restore after test

        ids = {v.id for v in results}
        assert "VND-CTX-B" not in ids, (
            "Contextvar-driven tenant A session must not see tenant B vendors"
        )

    async def test_contextvar_reset_between_tenants(
        self, db_factory: async_sessionmaker
    ) -> None:
        """
        Switching the contextvar to a different tenant between two sessions
        produces correctly scoped results each time (no bleed-over).
        """
        from tenant_context import get_current_tenant_id

        # Populate both tenants
        async with _make_session(db_factory, TENANT_A) as session_a:
            await VendorRepository(session_a).create(
                "VND-CV-A1", "CV Vendor A", tier="high", status="approved"
            )
            await session_a.commit()

        async with _make_session(db_factory, TENANT_B) as session_b:
            await VendorRepository(session_b).create(
                "VND-CV-B1", "CV Vendor B", tier="critical", status="approved"
            )
            await session_b.commit()

        # Act — query as tenant A using contextvar
        set_current_tenant_id(TENANT_A)
        try:
            async with db_factory() as session:
                session.info["tenant_id"] = get_current_tenant_id()
                results_a = list(await VendorRepository(session).list())
        finally:
            set_current_tenant_id(None)

        # Act — query as tenant B using contextvar (no bleed from previous call)
        set_current_tenant_id(TENANT_B)
        try:
            async with db_factory() as session:
                session.info["tenant_id"] = get_current_tenant_id()
                results_b = list(await VendorRepository(session).list())
        finally:
            set_current_tenant_id(None)

        ids_a = {v.id for v in results_a}
        ids_b = {v.id for v in results_b}

        # Tenant A sees its own record only
        assert "VND-CV-A1" in ids_a
        assert "VND-CV-B1" not in ids_a

        # Tenant B sees its own record only (same process, different contextvar value)
        assert "VND-CV-B1" in ids_b
        assert "VND-CV-A1" not in ids_b
