"""
Тесты для database.py, models.py и db_repository.py.

Покрывают: CRUD операции, repository pattern, миграцию, event sourcing.
Все тесты используют in-memory SQLite (не трогают файловую систему).

Запуск: python -m pytest tests/test_database.py -v
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

import pytest

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from database import Base, is_db_enabled
from db_repository import (
    AuditEventRepository,
    ControlRepository,
    EvidenceRepository,
    PolicyRepository,
    RiskRepository,
    TrainingRepository,
    VendorRepository,
)
from models import AuditEvent


# ── Фикстура: in-memory SQLite ────────────────────────────────────────────────

@pytest.fixture
async def session() -> AsyncGenerator[AsyncSession, None]:
    """
    Изолированная in-memory SQLite БД для каждого теста.
    Создаёт схему, отдаёт сессию, диспозирует после теста.
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as db:
        yield db

    await engine.dispose()


# ── Тест 1: EvidenceRepository.create ────────────────────────────────────────

async def test_evidence_create(session: AsyncSession) -> None:
    """Создание доказательства через репозиторий."""
    repo = EvidenceRepository(session)
    ev = await repo.create(
        control_id="CC6.1",
        title="Okta MFA enabled",
        content="MFA enforced for all users",
        source="okta",
    )
    await session.flush()

    assert ev.id is not None
    assert ev.control_id == "CC6.1"
    assert ev.title == "Okta MFA enabled"
    assert ev.source == "okta"
    assert ev.confidence_score is None


# ── Тест 2: EvidenceRepository.get ────────────────────────────────────────────

async def test_evidence_get_by_id(session: AsyncSession) -> None:
    """Получение доказательства по id."""
    repo = EvidenceRepository(session)
    ev = await repo.create("CC6.2", "Test", "content", "manual")
    await session.flush()

    fetched = await repo.get(ev.id)
    assert fetched is not None
    assert fetched.id == ev.id
    assert fetched.control_id == "CC6.2"


# ── Тест 3: EvidenceRepository.get возвращает None для несуществующего ────────

async def test_evidence_get_nonexistent(session: AsyncSession) -> None:
    """get() возвращает None для несуществующего id."""
    repo = EvidenceRepository(session)
    result = await repo.get("nonexistent-id-999")
    assert result is None


# ── Тест 4: EvidenceRepository.list_by_control ───────────────────────────────

async def test_evidence_list_by_control(session: AsyncSession) -> None:
    """list_by_control() возвращает только доказательства нужного контроля."""
    repo = EvidenceRepository(session)
    await repo.create("CC6.1", "T1", "c1", "s1")
    await repo.create("CC6.1", "T2", "c2", "s2")
    await repo.create("CC6.2", "T3", "c3", "s3")  # другой контроль
    await session.flush()

    results = await repo.list_by_control("CC6.1")
    assert len(results) == 2
    for ev in results:
        assert ev.control_id == "CC6.1"


# ── Тест 5: EvidenceRepository.update_confidence ─────────────────────────────

async def test_evidence_update_confidence(session: AsyncSession) -> None:
    """update_confidence() обновляет score у доказательства."""
    repo = EvidenceRepository(session)
    ev = await repo.create("CC6.3", "Title", "content", "aws")
    await session.flush()

    await repo.update_confidence(ev.id, 0.87)
    await session.flush()

    refreshed = await repo.get(ev.id)
    assert refreshed is not None
    assert abs(refreshed.confidence_score - 0.87) < 0.001


# ── Тест 6: ControlRepository.update_status (создание) ───────────────────────

async def test_control_update_status_create(session: AsyncSession) -> None:
    """update_status() создаёт запись если её нет."""
    repo = ControlRepository(session)
    cs = await repo.update_status("CC6.1", "PASS", updated_by="okta_agent")
    await session.flush()

    assert cs.control_id == "CC6.1"
    assert cs.status == "PASS"
    assert cs.updated_by == "okta_agent"


# ── Тест 7: ControlRepository.update_status (upsert) ─────────────────────────

async def test_control_update_status_upsert(session: AsyncSession) -> None:
    """update_status() обновляет существующую запись (upsert)."""
    repo = ControlRepository(session)
    await repo.update_status("CC6.2", "FAIL")
    await session.flush()

    updated = await repo.update_status("CC6.2", "PASS", updated_by="human")
    await session.flush()

    all_statuses = await repo.list_all()
    cc62_list = [s for s in all_statuses if s.control_id == "CC6.2"]
    assert len(cc62_list) == 1
    assert cc62_list[0].status == "PASS"
    assert updated.status == "PASS"


# ── Тест 8: ControlRepository.list_all ───────────────────────────────────────

async def test_control_list_all(session: AsyncSession) -> None:
    """list_all() возвращает все контроли."""
    repo = ControlRepository(session)
    await repo.update_status("CC6.1", "PASS")
    await repo.update_status("CC6.2", "FAIL")
    await repo.update_status("CC6.3", "PARTIAL")
    await session.flush()

    results = await repo.list_all()
    ids = {r.control_id for r in results}
    assert {"CC6.1", "CC6.2", "CC6.3"}.issubset(ids)


# ── Тест 9: RiskRepository.create ─────────────────────────────────────────────

async def test_risk_create(session: AsyncSession) -> None:
    """Создание записи риска."""
    repo = RiskRepository(session)
    risk = await repo.create(
        risk_id="RISK-001",
        title="SQL Injection Risk",
        likelihood=4,
        impact=5,
        score=20,
        status="open",
        control_id="CC6.1",
        category="access_control",
    )
    await session.flush()

    assert risk.id == "RISK-001"
    assert risk.likelihood == 4
    assert risk.impact == 5
    assert risk.score == 20
    assert risk.status == "open"


# ── Тест 10: RiskRepository.list с фильтрацией ──────────────────────────────

async def test_risk_list_filter(session: AsyncSession) -> None:
    """list() фильтрует по статусу."""
    repo = RiskRepository(session)
    await repo.create("RISK-A1", "Open Risk", 3, 3, 9, status="open")
    await repo.create("RISK-A2", "Closed Risk", 2, 2, 4, status="closed")
    await session.flush()

    open_risks = await repo.list(status="open")
    assert all(r.status == "open" for r in open_risks)
    assert any(r.id == "RISK-A1" for r in open_risks)


# ── Тест 11: RiskRepository.update_status ────────────────────────────────────

async def test_risk_update_status(session: AsyncSession) -> None:
    """update_status() меняет статус риска."""
    repo = RiskRepository(session)
    await repo.create("RISK-B1", "Test", 2, 3, 6, status="open")
    await session.flush()

    updated = await repo.update_status("RISK-B1", "mitigated")
    await session.flush()

    assert updated is not None
    assert updated.status == "mitigated"


# ── Тест 12: AuditEventRepository.append ─────────────────────────────────────

async def test_audit_event_append(session: AsyncSession) -> None:
    """append() добавляет событие в audit trail."""
    repo = AuditEventRepository(session)
    event = await repo.append(
        event_type="evidence.created",
        entity_type="evidence",
        entity_id="ev-001",
        actor="okta_agent",
        payload={"control_id": "CC6.2"},
    )
    await session.flush()

    assert event.id is not None
    assert event.event_type == "evidence.created"
    assert event.actor == "okta_agent"
    assert event.payload == {"control_id": "CC6.2"}


# ── Тест 13: AuditEventRepository.list_by_entity ─────────────────────────────

async def test_audit_event_list_by_entity(session: AsyncSession) -> None:
    """list_by_entity() возвращает события только для нужной сущности."""
    repo = AuditEventRepository(session)
    await repo.append("evidence.created", "evidence", "ev-001", "agent1")
    await repo.append("evidence.updated", "evidence", "ev-001", "agent2")
    await repo.append("control.updated", "control", "CC6.1", "system")
    await session.flush()

    events = await repo.list_by_entity("evidence", "ev-001")
    assert len(events) == 2
    assert all(e.entity_type == "evidence" for e in events)
    assert all(e.entity_id == "ev-001" for e in events)


# ── Тест 14: AuditEventRepository.replay_from ────────────────────────────────

async def test_audit_event_replay_from(session: AsyncSession) -> None:
    """replay_from() возвращает события начиная с заданного момента."""
    repo = AuditEventRepository(session)

    past = datetime(2026, 1, 1, tzinfo=timezone.utc)
    future = datetime(2026, 6, 1, tzinfo=timezone.utc)

    event1 = AuditEvent(
        event_type="risk.created",
        entity_type="risk",
        entity_id="RISK-001",
        actor="system",
        payload={},
        created_at=past,
    )
    event2 = AuditEvent(
        event_type="risk.updated",
        entity_type="risk",
        entity_id="RISK-001",
        actor="system",
        payload={},
        created_at=future,
    )
    session.add(event1)
    session.add(event2)
    await session.flush()

    cutoff = datetime(2026, 5, 1, tzinfo=timezone.utc)
    events = await repo.replay_from(since=cutoff)
    event_types = [e.event_type for e in events]
    assert "risk.updated" in event_types
    assert "risk.created" not in event_types


# ── Тест 15: VendorRepository CRUD ───────────────────────────────────────────

async def test_vendor_crud(session: AsyncSession) -> None:
    """Полный CRUD цикл для вендора."""
    repo = VendorRepository(session)

    vendor = await repo.create(
        vendor_id="VND-T01",
        name="Test Vendor",
        tier="critical",
        status="pending",
        dpa_signed=False,
        data={"category": "cloud", "risk_score": 50},
    )
    await session.flush()
    assert vendor.id == "VND-T01"
    assert vendor.tier == "critical"

    fetched = await repo.get("VND-T01")
    assert fetched is not None
    assert fetched.name == "Test Vendor"

    updated = await repo.update("VND-T01", status="approved", dpa_signed=True)
    await session.flush()
    assert updated is not None
    assert updated.status == "approved"
    assert updated.dpa_signed is True

    all_vendors = await repo.list()
    assert any(v.id == "VND-T01" for v in all_vendors)


# ── Тест 16: PolicyRepository CRUD ───────────────────────────────────────────

async def test_policy_crud(session: AsyncSession) -> None:
    """Создание и обновление статуса черновика политики."""
    repo = PolicyRepository(session)

    draft = await repo.create(
        policy_id="pol-001",
        control_id="CC6.1",
        title="Access Control Policy",
        content="All access must be MFA protected.",
        status="draft",
        created_by="ai:claude-haiku",
    )
    await session.flush()
    assert draft.status == "draft"

    updated = await repo.update_status(
        "pol-001",
        "approved",
        approved_by="human:admin@acme.com",
    )
    await session.flush()
    assert updated is not None
    assert updated.status == "approved"
    assert updated.approved_by == "human:admin@acme.com"


# ── Тест 17: TrainingRepository ───────────────────────────────────────────────

async def test_training_repository(session: AsyncSession) -> None:
    """Регистрация прохождения обучения и поиск по сотруднику."""
    repo = TrainingRepository(session)

    await repo.create(
        employee_id="alice@acme.com",
        course_id="aup",
        certificate_url="CERT-001",
        extra={"score": 100, "status": "passed"},
    )
    await repo.create(
        employee_id="alice@acme.com",
        course_id="security_awareness",
        certificate_url="CERT-002",
    )
    await repo.create(
        employee_id="bob@acme.com",
        course_id="aup",
    )
    await session.flush()

    alice_courses = await repo.list_by_employee("alice@acme.com")
    assert len(alice_courses) == 2

    aup_completions = await repo.list_by_course("aup")
    assert len(aup_completions) == 2


# ── Тест 18: is_db_enabled() возвращает False без DATABASE_URL ───────────────

def test_is_db_enabled_false_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """is_db_enabled() возвращает False если DATABASE_URL не задан."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert is_db_enabled() is False


# ── Тест 19: is_db_enabled() возвращает True с DATABASE_URL ──────────────────

def test_is_db_enabled_true_with_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """is_db_enabled() возвращает True если DATABASE_URL задан."""
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///./compliance.db")
    assert is_db_enabled() is True


# ── Тест 20: Миграция из JSON — risk_register ─────────────────────────────────

async def test_migration_risk_register(session: AsyncSession, tmp_path: Path) -> None:
    """Миграция из risk_register.json создаёт записи в БД."""
    import db_migration as mig

    risks_data = [
        {
            "id": "RISK-MIG-01",
            "title": "Test Migration Risk",
            "description": "Test",
            "source": "control",
            "control_id": "CC6.1",
            "likelihood": 3,
            "impact": 4,
            "risk_score": 12,
            "category": "access_control",
            "owner": "admin@test.com",
            "treatment": "mitigate",
            "treatment_plan": "",
            "status": "open",
            "jira_ticket": None,
            "created_at": "2026-05-22T21:49:50.170639+00:00",
            "updated_at": "2026-05-22T21:49:50.170653+00:00",
            "target_date": "2026-06-21",
        }
    ]
    risk_file = tmp_path / "risk_register.json"
    risk_file.write_text(json.dumps(risks_data), encoding="utf-8")

    original_path = mig._JSON_PATHS.get("risk_register")
    mig._JSON_PATHS["risk_register"] = risk_file
    try:
        count = await mig.migrate_risk_register(session, dry_run=False)
        await session.flush()
    finally:
        if original_path:
            mig._JSON_PATHS["risk_register"] = original_path

    assert count == 1
    repo = RiskRepository(session)
    risk = await repo.get("RISK-MIG-01")
    assert risk is not None
    assert risk.likelihood == 3
    assert risk.impact == 4


# ── Тест 21: Миграция — dry_run не создаёт записи ────────────────────────────

async def test_migration_dry_run(session: AsyncSession, tmp_path: Path) -> None:
    """dry_run=True не создаёт записи в БД."""
    import db_migration as mig

    risks_data = [
        {
            "id": "RISK-DRY-01",
            "title": "Dry",
            "likelihood": 1,
            "impact": 1,
            "risk_score": 1,
            "status": "open",
        }
    ]
    risk_file = tmp_path / "risk_register_dry.json"
    risk_file.write_text(json.dumps(risks_data), encoding="utf-8")

    original_path = mig._JSON_PATHS.get("risk_register")
    mig._JSON_PATHS["risk_register"] = risk_file
    try:
        count = await mig.migrate_risk_register(session, dry_run=True)
    finally:
        if original_path:
            mig._JSON_PATHS["risk_register"] = original_path

    assert count == 1  # считает, но не записывает
    repo = RiskRepository(session)
    risk = await repo.get("RISK-DRY-01")
    assert risk is None  # не создана в БД


# ── Тест 22: Миграция — idempotency (повторный запуск) ───────────────────────

async def test_migration_idempotent(session: AsyncSession, tmp_path: Path) -> None:
    """Повторный запуск миграции не создаёт дубликаты."""
    import db_migration as mig

    risks_data = [
        {
            "id": "RISK-IDEM-01",
            "title": "Idempotent",
            "likelihood": 2,
            "impact": 2,
            "risk_score": 4,
            "status": "open",
        }
    ]
    risk_file = tmp_path / "risk_idem.json"
    risk_file.write_text(json.dumps(risks_data), encoding="utf-8")

    original_path = mig._JSON_PATHS.get("risk_register")
    mig._JSON_PATHS["risk_register"] = risk_file
    try:
        count1 = await mig.migrate_risk_register(session, dry_run=False)
        await session.flush()
        count2 = await mig.migrate_risk_register(session, dry_run=False)
    finally:
        if original_path:
            mig._JSON_PATHS["risk_register"] = original_path

    assert count1 == 1
    assert count2 == 0  # уже существует, повторно не вставляем


# ── Тест 23: Миграция вендоров ────────────────────────────────────────────────

async def test_migration_vendors(session: AsyncSession, tmp_path: Path) -> None:
    """Миграция vendors.json создаёт записи вендоров."""
    import db_migration as mig

    vendors_data = [
        {
            "id": "VND-MIG-01",
            "name": "Migration Vendor",
            "criticality": "critical",
            "status": "approved",
            "dpa_signed": True,
            "last_review_date": "2026-01-15",
            "category": "cloud",
            "risk_score": 30,
        }
    ]
    vendors_file = tmp_path / "vendors.json"
    vendors_file.write_text(json.dumps(vendors_data), encoding="utf-8")

    original_path = mig._JSON_PATHS.get("vendors")
    mig._JSON_PATHS["vendors"] = vendors_file
    try:
        count = await mig.migrate_vendors(session, dry_run=False)
        await session.flush()
    finally:
        if original_path:
            mig._JSON_PATHS["vendors"] = original_path

    assert count == 1
    repo = VendorRepository(session)
    vendor = await repo.get("VND-MIG-01")
    assert vendor is not None
    assert vendor.tier == "critical"
    assert vendor.dpa_signed is True


# ── Тест 24: AuditEvent — payload хранится корректно ─────────────────────────

async def test_audit_event_payload_stored(session: AsyncSession) -> None:
    """AuditEvent хранит payload без изменений."""
    repo = AuditEventRepository(session)
    payload = {"before": "FAIL", "after": "PASS", "control_id": "CC6.1"}
    event = await repo.append(
        event_type="control.status_changed",
        entity_type="control",
        entity_id="CC6.1",
        payload=payload,
    )
    await session.flush()

    fetched_events = await repo.list_by_entity("control", "CC6.1")
    assert len(fetched_events) == 1
    stored_payload = fetched_events[0].payload
    assert stored_payload["before"] == "FAIL"
    assert stored_payload["after"] == "PASS"
    assert stored_payload["control_id"] == "CC6.1"


# ── Тест 25: EvidenceRepository — truncation длинного контента ───────────────

async def test_evidence_content_truncation(session: AsyncSession) -> None:
    """Контент обрезается до 99000 символов при create()."""
    repo = EvidenceRepository(session)
    long_content = "X" * 200_000
    ev = await repo.create("CC6.1", "Long Evidence", long_content, "test")
    await session.flush()

    assert len(ev.content) <= 99_000
