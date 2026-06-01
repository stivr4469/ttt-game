"""Tests for EvidenceRepository hash-chain logic (db_repository.py)."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hashlib
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from database import Base
import models  # noqa: F401 — registers ORM classes in Base.metadata

from db_repository import EvidenceRepository


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False, autoflush=False)
    async with factory() as s:
        yield s
    await engine.dispose()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


async def _ev(session, control_id="CC6.1", title="T", content="body", source="SCANNER"):
    """Shorthand: create one Evidence row."""
    repo = EvidenceRepository(session)
    return await repo.create(control_id=control_id, title=title, content=content, source=source)


# ── Hash value correctness ─────────────────────────────────────────────────────

class TestHashValues:
    async def test_content_hash_equals_sha256(self, session):
        ev = await _ev(session, content="hello-world")
        assert ev.content_hash == _sha256("hello-world")

    async def test_chain_valid_true_on_creation(self, session):
        ev = await _ev(session)
        assert ev.chain_valid is True


# ── Chain sequencing ───────────────────────────────────────────────────────────

class TestChainSequencing:
    async def test_first_evidence_has_null_previous_hash(self, session):
        ev = await _ev(session, content="first")
        assert ev.previous_hash is None

    async def test_second_chains_to_first(self, session):
        ev1 = await _ev(session, content="first")
        ev2 = await _ev(session, content="second")
        assert ev2.previous_hash == ev1.content_hash

    async def test_third_chains_to_second(self, session):
        ev1 = await _ev(session, content="aaa")
        ev2 = await _ev(session, content="bbb")
        ev3 = await _ev(session, content="ccc")
        assert ev2.previous_hash == ev1.content_hash
        assert ev3.previous_hash == ev2.content_hash

    async def test_different_controls_have_independent_chains(self, session):
        ev_a = await _ev(session, control_id="CC6.1", content="body-a")
        ev_b = await _ev(session, control_id="CC6.2", content="body-b")
        # Both are first in their respective chain
        assert ev_a.previous_hash is None
        assert ev_b.previous_hash is None

    async def test_interleaved_controls_chain_independently(self, session):
        a1 = await _ev(session, control_id="CC6.1", content="a1")
        b1 = await _ev(session, control_id="CC6.2", content="b1")
        a2 = await _ev(session, control_id="CC6.1", content="a2")
        b2 = await _ev(session, control_id="CC6.2", content="b2")
        assert a2.previous_hash == a1.content_hash
        assert b2.previous_hash == b1.content_hash


# ── Idempotency ────────────────────────────────────────────────────────────────

class TestIdempotency:
    async def test_same_content_returns_existing_record(self, session):
        repo = EvidenceRepository(session)
        ev1 = await repo.create("CC6.1", "Title", "same-body", "SCANNER")
        ev2 = await repo.create("CC6.1", "Title", "same-body", "SCANNER")
        assert ev1.id == ev2.id

    async def test_idempotent_insert_does_not_extend_chain(self, session):
        repo = EvidenceRepository(session)
        ev1 = await repo.create("CC6.1", "T", "body", "SCANNER")
        _    = await repo.create("CC6.1", "T", "body", "SCANNER")  # duplicate
        ev2  = await repo.create("CC6.1", "T", "body-new", "SCANNER")
        # ev2 should chain to ev1, not to duplicate
        assert ev2.previous_hash == ev1.content_hash

    async def test_different_source_is_not_idempotent(self, session):
        repo = EvidenceRepository(session)
        ev1 = await repo.create("CC6.1", "T", "body", "SCANNER")
        ev2 = await repo.create("CC6.1", "T", "body", "MANUAL")
        assert ev1.id != ev2.id


# ── Tenant isolation ───────────────────────────────────────────────────────────

class TestTenantIsolation:
    async def test_tenant_b_evidence_not_in_tenant_a_chain(self, session):
        """Tenant B writes first; Tenant A's first evidence must start a fresh chain."""
        session.info["tenant_id"] = "tenant-b"
        repo = EvidenceRepository(session)
        await repo.create("CC6.1", "B", "tenant-b-content", "SCANNER")

        session.info["tenant_id"] = "tenant-a"
        ev_a = await repo.create("CC6.1", "A", "tenant-a-content", "SCANNER")
        assert ev_a.previous_hash is None

    async def test_tenant_a_chain_continues_within_same_tenant(self, session):
        session.info["tenant_id"] = "tenant-a"
        repo = EvidenceRepository(session)
        ev1 = await repo.create("CC6.1", "T1", "a-body-1", "SCANNER")
        ev2 = await repo.create("CC6.1", "T2", "a-body-2", "SCANNER")
        assert ev2.previous_hash == ev1.content_hash

    async def test_cross_tenant_no_shared_state(self, session):
        """Both tenants build independent chains for the same control_id."""
        session.info["tenant_id"] = "tenant-x"
        repo = EvidenceRepository(session)
        x1 = await repo.create("CC6.1", "X1", "x-body-1", "SCANNER")
        x2 = await repo.create("CC6.1", "X2", "x-body-2", "SCANNER")

        session.info["tenant_id"] = "tenant-y"
        y1 = await repo.create("CC6.1", "Y1", "y-body-1", "SCANNER")
        y2 = await repo.create("CC6.1", "Y2", "y-body-2", "SCANNER")

        assert x2.previous_hash == x1.content_hash
        assert y1.previous_hash is None
        assert y2.previous_hash == y1.content_hash
