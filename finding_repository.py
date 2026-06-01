"""
Repository для Finding - нативной сущности compliance-findings.

Логика:
- FAIL -> open_or_update(): создать finding или обновить last_seen_at
- PASS -> resolve(): закрыть открытый finding
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from models import Finding, TestDefinition

_SLA_DAYS: dict[str, int] = {
    "CRITICAL": 1,
    "HIGH": 7,
    "MEDIUM": 30,
    "LOW": 90,
}


class FindingRepository:
    """Инкапсулирует все операции с таблицей findings."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def open_or_update(
        self,
        test: TestDefinition,
        resource_id: str,
        result_id: str,
    ) -> Finding:
        """Создать finding при FAIL или обновить last_seen_at если уже открыт."""
        now = datetime.now(timezone.utc)
        severity = test.severity
        sla_days = _SLA_DAYS.get(severity, 30)

        from database import get_tenant_id_from_session
        _tenant_id = get_tenant_id_from_session(self._session)

        existing = await self._session.scalar(
            select(Finding).where(
                Finding.test_id == test.id,
                Finding.resource_id == resource_id,
                Finding.status == "OPEN",
            )
        )

        if existing:
            existing.last_seen_at = now
            existing.result_id = result_id
            await self._session.flush()
            return existing

        finding = Finding(
            test_id=test.id,
            resource_id=resource_id,
            status="OPEN",
            severity=severity,
            title=test.title,
            first_seen_at=now,
            last_seen_at=now,
            sla_due_at=now + timedelta(days=sla_days),
            result_id=result_id,
            tenant_id=_tenant_id,
        )
        self._session.add(finding)
        await self._session.flush()
        return finding

    async def resolve(self, test_id: str, resource_id: str) -> None:
        """Закрыть finding когда тест снова PASS."""
        now = datetime.now(timezone.utc)
        await self._session.execute(
            sa_update(Finding)
            .where(
                Finding.test_id == test_id,
                Finding.resource_id == resource_id,
                Finding.status == "OPEN",
            )
            .values(status="RESOLVED", resolved_at=now)
        )

    async def list_by_status(
        self,
        status: str = "OPEN",
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Finding]:
        """Вернуть findings по статусу с опциональной фильтрацией по severity."""
        from database import get_tenant_id_from_session
        stmt = (
            select(Finding)
            .where(Finding.status == status.upper())
            .order_by(Finding.first_seen_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if severity:
            stmt = stmt.where(Finding.severity == severity.upper())
        tenant_id = get_tenant_id_from_session(self._session)
        if tenant_id:
            stmt = stmt.where(Finding.tenant_id == tenant_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(
        self,
        finding_id: str,
        new_status: str,
    ) -> Optional[Finding]:
        """Обновить статус finding (RESOLVED, FALSE_POSITIVE, ACCEPTED_RISK)."""
        finding = await self._session.get(Finding, finding_id)
        if not finding:
            return None
        finding.status = new_status
        if new_status == "RESOLVED":
            finding.resolved_at = datetime.now(timezone.utc)
        await self._session.flush()
        return finding

    async def assign_owner(
        self,
        finding_id: str,
        owner_email: str,
    ) -> Optional[Finding]:
        """Назначить владельца finding."""
        finding = await self._session.get(Finding, finding_id)
        if not finding:
            return None
        finding.owner_email = owner_email
        await self._session.flush()
        return finding
