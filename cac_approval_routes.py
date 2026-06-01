"""
cac_approval_routes.py — Approval workflow для CaC auto-remediation.

Эндпоинты:
  POST /api/v1/cac/remediation/request        — запросить выполнение команды (auditor+)
  GET  /api/v1/cac/remediation/pending        — список pending (auditor+)
  POST /api/v1/cac/remediation/{id}/approve   — одобрить (admin)
  POST /api/v1/cac/remediation/{id}/reject    — отклонить (admin)
  POST /api/v1/cac/remediation/{id}/execute   — выполнить approved (admin)
  GET  /api/v1/cac/remediation/{id}           — статус/результат (auth)

Регистрация в ui_server.py:
    from cac_approval_routes import router as cac_approval_router
    app.include_router(cac_approval_router)
"""

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_admin, require_auditor, require_auth
from cac_sandbox import run_command, ALLOWED_COMMANDS
from database import get_db, get_tenant_id_from_session
from models import RemediationApproval

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cac/remediation", tags=["cac-remediation"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class RemediationRequestBody(BaseModel):
    control_id: str
    command: str
    dry_run: bool = True
    tenant_id: Optional[str] = None


class RejectBody(BaseModel):
    reason: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _approval_to_dict(approval: RemediationApproval) -> dict:
    return {
        "id": approval.id,
        "tenant_id": approval.tenant_id,
        "control_id": approval.control_id,
        "command": approval.command,
        "requested_by": approval.requested_by,
        "approved_by": approval.approved_by,
        "status": approval.status,
        "dry_run": approval.dry_run,
        "result": json.loads(approval.result) if approval.result else None,
        "created_at": approval.created_at.isoformat() if approval.created_at else None,
        "executed_at": approval.executed_at.isoformat() if approval.executed_at else None,
    }


async def _get_approval_or_404(approval_id: str, db: AsyncSession) -> RemediationApproval:
    result = await db.execute(
        select(RemediationApproval).where(RemediationApproval.id == approval_id)
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail=f"Approval '{approval_id}' не найден")
    return approval


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/request", status_code=201)
async def request_remediation(
    body: RemediationRequestBody,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_auditor),
):
    """
    Запросить выполнение remediation-команды.

    Создаёт запись со статусом 'pending' — требует одобрения admin.
    """
    # Валидация команды против allowlist перед сохранением
    cmd_parts = body.command.split()
    if not cmd_parts:
        raise HTTPException(status_code=400, detail="Command cannot be empty")
    binary = cmd_parts[0].split("/")[-1]
    if binary not in ALLOWED_COMMANDS:
        raise HTTPException(status_code=400, detail=f"Binary '{binary}' not in allowlist")

    actor = user.get("sub") or user.get("email", "unknown")
    approval = RemediationApproval(
        control_id=body.control_id,
        command=body.command,
        requested_by=actor,
        dry_run=body.dry_run,
        tenant_id=body.tenant_id,
        status="pending",
    )
    db.add(approval)
    await db.flush()  # получаем id до commit
    await db.commit()
    log.info(
        "CaC remediation requested: id=%s control=%s by=%s dry_run=%s",
        approval.id,
        approval.control_id,
        actor,
        approval.dry_run,
    )
    return {"status": "pending", "approval": _approval_to_dict(approval)}


@router.get("/pending")
async def list_pending(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_auditor),
):
    """Список всех remediation-запросов со статусом pending."""
    tenant_id = get_tenant_id_from_session(db)
    stmt = (
        select(RemediationApproval)
        .where(RemediationApproval.status == "pending")
        .order_by(RemediationApproval.created_at.desc())
    )
    if tenant_id:
        stmt = stmt.where(RemediationApproval.tenant_id == tenant_id)
    result = await db.execute(stmt)
    approvals = result.scalars().all()
    return {
        "total": len(approvals),
        "pending": [_approval_to_dict(a) for a in approvals],
    }


@router.post("/{approval_id}/approve")
async def approve_remediation(
    approval_id: str,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """
    Одобрить pending remediation (только admin).

    После одобрения статус меняется на 'approved'. Команда выполняется
    отдельным вызовом /{id}/execute.
    """
    approval = await _get_approval_or_404(approval_id, db)
    if approval.status != "pending":
        raise HTTPException(
            status_code=409,
            detail=f"Approval имеет статус '{approval.status}', ожидается 'pending'",
        )
    actor = user.get("sub") or user.get("email", "unknown")
    approval.approved_by = actor
    approval.status = "approved"
    log.info("CaC remediation approved: id=%s by=%s", approval_id, actor)
    return {"status": "approved", "approval": _approval_to_dict(approval)}


@router.post("/{approval_id}/reject")
async def reject_remediation(
    approval_id: str,
    body: RejectBody = RejectBody(),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """
    Отклонить pending remediation (только admin).

    Опциональная причина сохраняется в поле result в виде JSON.
    """
    approval = await _get_approval_or_404(approval_id, db)
    if approval.status not in ("pending", "approved"):
        raise HTTPException(
            status_code=409,
            detail=f"Approval имеет статус '{approval.status}', нельзя отклонить",
        )
    actor = user.get("sub") or user.get("email", "unknown")
    approval.status = "rejected"
    approval.approved_by = actor
    if body.reason:
        approval.result = json.dumps({"rejected_by": actor, "reason": body.reason})
    log.info("CaC remediation rejected: id=%s by=%s reason=%s", approval_id, actor, body.reason)
    return {"status": "rejected", "approval": _approval_to_dict(approval)}


@router.post("/{approval_id}/execute")
async def execute_remediation(
    approval_id: str,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_admin),
):
    """
    Выполнить approved remediation-команду в CaC Sandbox (только admin).

    Шаги:
    1. Проверить status == 'approved'
    2. Запустить команду через cac_sandbox.run_command()
    3. Сохранить результат (JSON SandboxResult)
    4. Обновить статус → 'executed', записать executed_at
    """
    approval = await _get_approval_or_404(approval_id, db)
    if approval.status != "approved":
        raise HTTPException(
            status_code=409,
            detail=f"Approval имеет статус '{approval.status}', ожидается 'approved'",
        )

    actor = user.get("sub") or user.get("email", "unknown")
    log.info(
        "CaC remediation executing: id=%s control=%s command='%s' dry_run=%s by=%s",
        approval_id,
        approval.control_id,
        approval.command,
        approval.dry_run,
        actor,
    )

    sandbox_result = await run_command(
        command=approval.command,
        dry_run=approval.dry_run,
    )

    approval.result = json.dumps(asdict(sandbox_result))
    approval.status = "executed"
    approval.executed_at = datetime.now(timezone.utc)

    log.info(
        "CaC remediation executed: id=%s success=%s exit_code=%d duration_ms=%.1f",
        approval_id,
        sandbox_result.success,
        sandbox_result.exit_code,
        sandbox_result.duration_ms,
    )
    return {
        "status": "executed",
        "approval": _approval_to_dict(approval),
    }


@router.get("/{approval_id}")
async def get_remediation(
    approval_id: str,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(require_auth),
):
    """Получить статус и результат remediation по ID."""
    approval = await _get_approval_or_404(approval_id, db)
    return _approval_to_dict(approval)
