"""
Audit Log API — просмотр журнала действий пользователей (A11).

GET /api/v1/audit-log              — последние N записей (по умолчанию 100)
GET /api/v1/audit-log/by-user/{email} — записи конкретного пользователя

Доступ: только роли admin и auditor (require_auditor).
"""
import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from audit_log_repository import AuditLogRepository
from auth import require_auditor
from database import get_db

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/audit-log", tags=["audit-log"])


def _serialize(entry) -> dict:
    return {
        "id": entry.id,
        "timestamp": entry.timestamp.isoformat(),
        "user_email": entry.user_email,
        "user_role": entry.user_role,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "detail": entry.detail,
        "ip_address": entry.ip_address,
    }


@router.get("")
async def get_audit_log(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    payload: dict = Depends(require_auditor),
    session: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Последние записи журнала действий (требует роль admin или auditor)."""
    repo = AuditLogRepository(session)
    entries = await repo.recent(limit=limit, offset=offset)
    return [_serialize(e) for e in entries]


@router.get("/by-user/{email}")
async def get_user_audit_log(
    email: str,
    limit: int = Query(50, ge=1, le=200),
    payload: dict = Depends(require_auditor),
    session: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Записи журнала для конкретного пользователя (требует роль admin или auditor)."""
    repo = AuditLogRepository(session)
    entries = await repo.by_user(email=email, limit=limit)
    return [_serialize(e) for e in entries]
