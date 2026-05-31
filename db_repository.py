"""
Repository pattern поверх SQLAlchemy ORM-моделей.

Каждый репозиторий инкапсулирует операции с одной таблицей.
Все методы async — работают с AsyncSession из database.py.

Репозитории:
  EvidenceRepository   — управление доказательствами
  ControlRepository    — статусы контролей
  RiskRepository       — реестр рисков
  AuditEventRepository — append-only audit trail (event sourcing)
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditEvent, ControlStatus, Evidence, RiskEntry, Vendor, PolicyDraft, TrainingCompletion


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _new_uuid() -> str:
    """Генерирует новый UUID4 как строку."""
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    """Текущее время UTC."""
    return datetime.now(timezone.utc)


# ── EvidenceRepository ────────────────────────────────────────────────────────

class EvidenceRepository:
    """
    CRUD для таблицы evidence.

    Методы:
      create()              — создать новое доказательство
      list_by_control()     — получить все доказательства по control_id
      get()                 — получить по id
      update_confidence()   — обновить confidence_score
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        control_id: str,
        title: str,
        content: str,
        source: str,
        confidence_score: Optional[float] = None,
        evidence_id: Optional[str] = None,
    ) -> Evidence:
        """
        Идемпотентно создаёт доказательство.
        Если запись с тем же (control_id, source, content_hash) уже существует —
        возвращает её без INSERT. evidence_id можно передать явно (для миграции из JSON).
        """
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Проверка дубликата по (control_id, source, content_hash)
        existing = await self._session.execute(
            select(Evidence).where(
                Evidence.control_id == control_id,
                Evidence.source == source,
                Evidence.content_hash == content_hash,
            )
        )
        found = existing.scalar_one_or_none()
        if found:
            return found  # идемпотентно — возвращаем существующий

        ev = Evidence(
            id=evidence_id or _new_uuid(),
            control_id=control_id,
            title=title[:500],           # лимит сервера 500 символов
            content=content[:99_000],    # лимит 100 KB
            source=source,
            confidence_score=confidence_score,
            content_hash=content_hash,
            created_at=_utcnow(),
        )
        self._session.add(ev)
        try:
            await self._session.flush()  # получаем id без commit
        except IntegrityError:
            await self._session.rollback()
            # Гонка — другой воркер вставил первым, достаём его запись
            result = await self._session.execute(
                select(Evidence).where(
                    Evidence.control_id == control_id,
                    Evidence.source == source,
                    Evidence.content_hash == content_hash,
                )
            )
            return result.scalar_one()
        return ev

    async def get(self, evidence_id: str) -> Optional[Evidence]:
        """Возвращает доказательство по id или None."""
        result = await self._session.get(Evidence, evidence_id)
        return result

    async def list_by_control(
        self,
        control_id: str,
        limit: int = 100,
    ) -> Sequence[Evidence]:
        """Возвращает доказательства для данного контроля, сортировка по дате."""
        stmt = (
            select(Evidence)
            .where(Evidence.control_id == control_id)
            .order_by(Evidence.created_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def list_all(self, limit: int = 100) -> Sequence[Evidence]:
        """Возвращает все доказательства (для отчётов)."""
        stmt = select(Evidence).order_by(Evidence.created_at.desc()).limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def update_confidence(
        self,
        evidence_id: str,
        confidence_score: float,
    ) -> Optional[Evidence]:
        """Обновляет confidence_score для доказательства."""
        ev = await self.get(evidence_id)
        if ev is None:
            return None
        ev.confidence_score = confidence_score
        await self._session.flush()
        return ev


# ── ControlRepository ─────────────────────────────────────────────────────────

class ControlRepository:
    """
    Управление статусами SOC2 контролей.

    Методы:
      get_status()    — получить текущий статус
      update_status() — upsert статус
      list_all()      — список всех контролей с их статусами
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_status(self, control_id: str) -> Optional[ControlStatus]:
        """Возвращает текущий статус контроля или None."""
        stmt = select(ControlStatus).where(ControlStatus.control_id == control_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_status(
        self,
        control_id: str,
        status: str,
        updated_by: str = "system",
    ) -> ControlStatus:
        """
        Upsert статус контроля.
        Если запись существует — обновляет, иначе создаёт новую.
        """
        existing = await self.get_status(control_id)
        if existing:
            existing.status = status
            existing.updated_at = _utcnow()
            existing.updated_by = updated_by
            await self._session.flush()
            return existing
        else:
            cs = ControlStatus(
                control_id=control_id,
                status=status,
                updated_at=_utcnow(),
                updated_by=updated_by,
            )
            self._session.add(cs)
            await self._session.flush()
            return cs

    async def list_all(self) -> Sequence[ControlStatus]:
        """Возвращает все записи статусов, сортировка по control_id."""
        stmt = select(ControlStatus).order_by(ControlStatus.control_id)
        result = await self._session.execute(stmt)
        return result.scalars().all()


# ── RiskRepository ────────────────────────────────────────────────────────────

class RiskRepository:
    """
    Реестр рисков.

    Методы:
      create()        — создать запись риска
      list()          — список с фильтрацией
      update_status() — изменить статус риска
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        risk_id: str,
        title: str,
        likelihood: int,
        impact: int,
        score: int,
        status: str = "open",
        control_id: Optional[str] = None,
        description: str = "",
        source: str = "manual",
        category: str = "operational",
        owner: Optional[str] = None,
        treatment: str = "mitigate",
        treatment_plan: str = "",
        jira_ticket: Optional[str] = None,
        target_date: Optional[str] = None,
    ) -> RiskEntry:
        """Создаёт новую запись в реестре рисков."""
        entry = RiskEntry(
            id=risk_id,
            control_id=control_id,
            title=title,
            description=description,
            source=source,
            likelihood=likelihood,
            impact=impact,
            score=score,
            category=category,
            owner=owner,
            treatment=treatment,
            treatment_plan=treatment_plan,
            status=status,
            jira_ticket=jira_ticket,
            target_date=target_date,
            created_at=_utcnow(),
            updated_at=_utcnow(),
        )
        self._session.add(entry)
        await self._session.flush()
        return entry

    async def get(self, risk_id: str) -> Optional[RiskEntry]:
        """Возвращает запись риска по id или None."""
        return await self._session.get(RiskEntry, risk_id)

    async def list(
        self,
        status: Optional[str] = None,
        category: Optional[str] = None,
        control_id: Optional[str] = None,
        limit: int = 200,
    ) -> Sequence[RiskEntry]:
        """Возвращает риски с опциональной фильтрацией."""
        stmt = select(RiskEntry).order_by(RiskEntry.created_at.desc())
        if status:
            stmt = stmt.where(RiskEntry.status == status)
        if category:
            stmt = stmt.where(RiskEntry.category == category)
        if control_id:
            stmt = stmt.where(RiskEntry.control_id == control_id)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def update_status(
        self,
        risk_id: str,
        status: str,
    ) -> Optional[RiskEntry]:
        """Обновляет статус риска. Возвращает обновлённую запись или None."""
        entry = await self.get(risk_id)
        if not entry:
            return None
        entry.status = status
        entry.updated_at = _utcnow()
        await self._session.flush()
        return entry


# ── AuditEventRepository ──────────────────────────────────────────────────────

class AuditEventRepository:
    """
    Append-only репозиторий для audit trail (event sourcing).

    ВАЖНО: записи никогда не удаляются и не изменяются.
    Это обеспечивает audit defensibility для SOC2.

    Методы:
      append()          — добавить новое событие
      replay_from()     — воспроизвести события начиная с момента времени
      list_by_entity()  — события по типу/id сущности
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        event_type: str,
        entity_type: str,
        entity_id: str,
        actor: str = "system",
        payload: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        Добавляет событие в audit trail.

        Пример:
          await repo.append(
              event_type="evidence.created",
              entity_type="evidence",
              entity_id=ev.id,
              actor="agent:okta",
              payload={"control_id": "CC6.2"},
          )
        """
        event = AuditEvent(
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            actor=actor,
            payload=payload or {},
            created_at=_utcnow(),
        )
        self._session.add(event)
        await self._session.flush()
        return event

    async def replay_from(
        self,
        since: datetime,
        event_type: Optional[str] = None,
    ) -> Sequence[AuditEvent]:
        """
        Воспроизводит все события начиная с момента since (включительно).
        Опционально фильтрует по event_type.
        """
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.created_at >= since)
            .order_by(AuditEvent.created_at.asc())
        )
        if event_type:
            stmt = stmt.where(AuditEvent.event_type == event_type)
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def list_by_entity(
        self,
        entity_type: str,
        entity_id: str,
        limit: int = 100,
    ) -> Sequence[AuditEvent]:
        """Возвращает все события для конкретной сущности."""
        stmt = (
            select(AuditEvent)
            .where(
                AuditEvent.entity_type == entity_type,
                AuditEvent.entity_id == entity_id,
            )
            .order_by(AuditEvent.created_at.asc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def list_recent(self, limit: int = 100) -> Sequence[AuditEvent]:
        """Возвращает последние N событий (для дашборда)."""
        stmt = (
            select(AuditEvent)
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()


# ── VendorRepository ──────────────────────────────────────────────────────────

class VendorRepository:
    """
    Реестр вендоров.

    Методы:
      create()     — добавить вендора
      get()        — получить по id
      update()     — обновить поля
      list()       — список с фильтрацией
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        vendor_id: str,
        name: str,
        tier: str = "medium",
        status: str = "pending",
        dpa_signed: bool = False,
        last_review_date: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Vendor:
        """Создаёт нового вендора."""
        vendor = Vendor(
            id=vendor_id,
            name=name,
            tier=tier,
            status=status,
            dpa_signed=dpa_signed,
            last_review_date=last_review_date,
            data=data or {},
        )
        self._session.add(vendor)
        await self._session.flush()
        return vendor

    async def get(self, vendor_id: str) -> Optional[Vendor]:
        """Возвращает вендора по id или None."""
        return await self._session.get(Vendor, vendor_id)

    async def update(
        self,
        vendor_id: str,
        **fields: Any,
    ) -> Optional[Vendor]:
        """Обновляет произвольные поля вендора."""
        vendor = await self.get(vendor_id)
        if not vendor:
            return None
        for key, value in fields.items():
            if hasattr(vendor, key):
                setattr(vendor, key, value)
        await self._session.flush()
        return vendor

    async def list(
        self,
        status: Optional[str] = None,
        tier: Optional[str] = None,
    ) -> Sequence[Vendor]:
        """Возвращает вендоров с опциональной фильтрацией."""
        stmt = select(Vendor).order_by(Vendor.name)
        if status:
            stmt = stmt.where(Vendor.status == status)
        if tier:
            stmt = stmt.where(Vendor.tier == tier)
        result = await self._session.execute(stmt)
        return result.scalars().all()


# ── PolicyRepository ──────────────────────────────────────────────────────────

class PolicyRepository:
    """
    Черновики политик.

    Методы:
      create()         — создать черновик
      get()            — получить по id
      update_status()  — изменить статус
      list_by_control() — черновики для контроля
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        policy_id: str,
        control_id: str,
        title: str,
        content: str,
        status: str = "draft",
        created_by: str = "system",
        approved_by: Optional[str] = None,
    ) -> PolicyDraft:
        """Создаёт черновик политики."""
        draft = PolicyDraft(
            id=policy_id,
            control_id=control_id,
            title=title,
            content=content,
            status=status,
            created_by=created_by,
            approved_by=approved_by,
            created_at=_utcnow(),
        )
        self._session.add(draft)
        await self._session.flush()
        return draft

    async def get(self, policy_id: str) -> Optional[PolicyDraft]:
        """Возвращает черновик по id или None."""
        return await self._session.get(PolicyDraft, policy_id)

    async def update_status(
        self,
        policy_id: str,
        status: str,
        approved_by: Optional[str] = None,
    ) -> Optional[PolicyDraft]:
        """Обновляет статус черновика."""
        draft = await self.get(policy_id)
        if not draft:
            return None
        draft.status = status
        if approved_by:
            draft.approved_by = approved_by
        await self._session.flush()
        return draft

    async def list_by_control(self, control_id: str) -> Sequence[PolicyDraft]:
        """Возвращает все черновики для данного контроля."""
        stmt = (
            select(PolicyDraft)
            .where(PolicyDraft.control_id == control_id)
            .order_by(PolicyDraft.created_at.desc())
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()


# ── TrainingRepository ────────────────────────────────────────────────────────

class TrainingRepository:
    """
    Записи о прохождении обучения.

    Методы:
      create()            — зарегистрировать прохождение
      list_by_employee()  — все курсы сотрудника
      list_by_course()    — все прохождения курса
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        employee_id: str,
        course_id: str,
        completed_at: Optional[datetime] = None,
        certificate_url: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> TrainingCompletion:
        """Регистрирует прохождение курса."""
        record = TrainingCompletion(
            employee_id=employee_id,
            course_id=course_id,
            completed_at=completed_at or _utcnow(),
            certificate_url=certificate_url,
            extra=extra or {},
        )
        self._session.add(record)
        await self._session.flush()
        return record

    async def list_by_employee(self, employee_id: str) -> Sequence[TrainingCompletion]:
        """Все записи обучения для данного сотрудника."""
        stmt = (
            select(TrainingCompletion)
            .where(TrainingCompletion.employee_id == employee_id)
            .order_by(TrainingCompletion.completed_at.desc())
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()

    async def list_by_course(self, course_id: str) -> Sequence[TrainingCompletion]:
        """Все прохождения данного курса."""
        stmt = (
            select(TrainingCompletion)
            .where(TrainingCompletion.course_id == course_id)
            .order_by(TrainingCompletion.completed_at.desc())
        )
        result = await self._session.execute(stmt)
        return result.scalars().all()
