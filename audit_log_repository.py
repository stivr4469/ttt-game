"""
AuditLogRepository — запись и чтение журнала действий пользователей.

Журнал «кто/что/когда» (A11 из SOC2-roadmap). Пишется при каждой
мутирующей операции. Предназначен для аудиторов — отдельно от
технических логов приложения.
"""
import uuid

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models import AuditLog


class AuditLogRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def log(
        self,
        user_email: str,
        user_role: str,
        action: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        detail: dict | None = None,
        ip_address: str | None = None,
    ) -> AuditLog:
        """Записать одно действие пользователя. flush() без commit() — вызывающий коммитит сам."""
        from database import get_tenant_id_from_session
        entry = AuditLog(
            id=str(uuid.uuid4()),
            user_email=user_email,
            user_role=user_role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            detail=detail,
            ip_address=ip_address,
            tenant_id=get_tenant_id_from_session(self._session),
        )
        self._session.add(entry)
        await self._session.flush()
        return entry

    async def recent(self, limit: int = 100, offset: int = 0) -> list[AuditLog]:
        """Последние записи в обратном хронологическом порядке."""
        from database import get_tenant_id_from_session
        stmt = (
            select(AuditLog)
            .order_by(desc(AuditLog.timestamp))
            .limit(limit)
            .offset(offset)
        )
        tenant_id = get_tenant_id_from_session(self._session)
        if tenant_id:
            stmt = stmt.where(AuditLog.tenant_id == tenant_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def by_user(self, email: str, limit: int = 50) -> list[AuditLog]:
        """Последние записи конкретного пользователя."""
        from database import get_tenant_id_from_session
        stmt = (
            select(AuditLog)
            .where(AuditLog.user_email == email)
            .order_by(desc(AuditLog.timestamp))
            .limit(limit)
        )
        tenant_id = get_tenant_id_from_session(self._session)
        if tenant_id:
            stmt = stmt.where(AuditLog.tenant_id == tenant_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
