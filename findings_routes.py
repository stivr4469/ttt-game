"""
Findings API — CRUD поверх нативной сущности Finding.

GET  /api/v1/findings          — список findings (по умолчанию status=OPEN)
PATCH /api/v1/findings/{id}    — обновить статус / назначить владельца
"""
from __future__ import annotations

import asyncio
import datetime as _dt

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_auth, require_auditor
from database import get_db, get_tenant_id_from_session
from finding_repository import FindingRepository
from models import Finding

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

_VALID_STATUSES = {"OPEN", "RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"}


def _serialize(f: Finding) -> dict:
    now = _dt.datetime.now(_dt.timezone.utc)
    return {
        "id": f.id,
        "test_key": f.test.key if f.test else None,
        "test_title": f.test.title if f.test else f.title,
        "resource_id": f.resource_id,
        "status": f.status,
        "severity": f.severity,
        "owner_email": f.owner_email,
        "first_seen_at": f.first_seen_at.isoformat(),
        "last_seen_at": f.last_seen_at.isoformat(),
        "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
        "sla_due_at": f.sla_due_at.isoformat() if f.sla_due_at else None,
        "sla_breached": (
            f.sla_due_at is not None
            and f.status == "OPEN"
            and f.sla_due_at < now
        ),
    }


@router.get("")
async def list_findings(
    status: str = Query("OPEN"),
    severity: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: dict = Depends(require_auth),
    session: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Список findings. status=OPEN по умолчанию."""
    if status.upper() not in _VALID_STATUSES:
        raise HTTPException(400, f"status must be one of {_VALID_STATUSES}")
    repo = FindingRepository(session)
    findings = await repo.list_by_status(status=status.upper(), severity=severity, limit=limit, offset=offset)
    return [_serialize(f) for f in findings]


class StatusUpdate(BaseModel):
    status: str
    owner_email: str | None = None


@router.patch("/{finding_id}")
async def update_finding(
    finding_id: str,
    body: StatusUpdate,
    payload: dict = Depends(require_auditor),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Обновить статус finding. Требует роль auditor."""
    if body.status.upper() not in _VALID_STATUSES:
        raise HTTPException(400, f"status must be one of {_VALID_STATUSES}")
    repo = FindingRepository(session)
    # Fetch and verify tenant ownership before mutating
    finding = await session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    tenant_id = get_tenant_id_from_session(session)
    if tenant_id and finding.tenant_id != tenant_id:
        raise HTTPException(404, "Finding not found")
    finding = await repo.update_status(finding_id, body.status.upper())
    if not finding:
        raise HTTPException(404, "Finding not found")
    if body.owner_email:
        await repo.assign_owner(finding_id, body.owner_email)
    await session.commit()

    if body.status.upper() in ("RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"):
        from outgoing_webhook_service import deliver as _wh_deliver
        asyncio.create_task(_wh_deliver("finding.resolved", {
            "finding_id": finding_id,
            "status": body.status.upper(),
            "test_key": finding.test.key if finding.test else None,
            "resource_id": finding.resource_id,
            "severity": finding.severity,
        }))

    return _serialize(finding)
