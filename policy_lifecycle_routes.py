"""
Policy Lifecycle API Routes — Segregation of Duties для SOC2 политик.

Префикс: /api/policy-lifecycle

Правило SoD:
  AI генерирует → status: "draft"
  Human approves (admin only) → status: "approved" → контрол = PASS
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from auth import require_auth, require_admin, require_auditor
from policy_lifecycle import PolicyLifecycleManager, PolicyStatus

router = APIRouter(prefix="/api/policy-lifecycle", tags=["policy-lifecycle"])

_plm = PolicyLifecycleManager()


# ── Pydantic-схемы запросов ───────────────────────────────────────────────────

class RejectRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=2000, description="Причина отклонения")


class ReviseRequest(BaseModel):
    content: str = Field(..., min_length=1, description="Обновлённый текст политики")


# ── Хелпер: сериализация ──────────────────────────────────────────────────────

def _serialize(record) -> dict:
    """Конвертировать PolicyRecord в dict для JSON-ответа."""
    d = asdict(record)
    d["status"] = record.status.value
    return d


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_policies(
    status: Optional[str] = Query(None, description="Фильтр по статусу: draft/pending_review/approved/rejected/expired"),
    control: Optional[str] = Query(None, description="Фильтр по коду контрола, например CC6.1"),
    user: dict = Depends(require_auth),
):
    """
    Получить список всех политик.

    Опциональные фильтры: ?status=draft&control=CC6.1
    """
    # Валидация статуса
    if status and status not in {s.value for s in PolicyStatus}:
        raise HTTPException(
            status_code=422,
            detail=f"Неверный статус '{status}'. "
                   f"Допустимые: {[s.value for s in PolicyStatus]}",
        )
    records = _plm.get_all(status=status, control_code=control)
    return {"policies": [_serialize(r) for r in records], "count": len(records)}


@router.get("/summary")
async def get_summary(user: dict = Depends(require_auth)):
    """Статистика по статусам: сколько draft/pending/approved/rejected/expired."""
    return _plm.get_summary()


@router.get("/pending")
async def list_pending(user: dict = Depends(require_auth)):
    """Только политики в статусе pending_review — для dashboard ревьюера."""
    records = _plm.get_all(status=PolicyStatus.PENDING_REVIEW.value)
    return {"policies": [_serialize(r) for r in records], "count": len(records)}


@router.get("/{policy_id}")
async def get_policy(policy_id: str, user: dict = Depends(require_auth)):
    """Получить одну политику по ID."""
    record = _plm.get_by_id(policy_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Политика {policy_id} не найдена")
    return _serialize(record)


@router.post("/{policy_id}/submit")
async def submit_for_review(
    policy_id: str,
    user: dict = Depends(require_auditor),
):
    """
    Подать черновик на ревью: draft → pending_review.

    Доступно: admin, auditor.
    """
    try:
        record = _plm.submit_for_review(policy_id)
        return {"message": "Политика подана на ревью", "policy": _serialize(record)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{policy_id}/approve")
async def approve_policy(
    policy_id: str,
    user: dict = Depends(require_admin),
):
    """
    Одобрить политику: pending_review → approved → контрол PASS.

    Только admin (SoD: approve не может делать тот же агент что генерировал).
    """
    try:
        approver = user.get("email", user.get("sub", "unknown"))
        record = _plm.approve(policy_id, approver=approver)
        return {
            "message": f"Политика одобрена. Контрол {record.control_code} переведён в PASS.",
            "policy": _serialize(record),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{policy_id}/reject")
async def reject_policy(
    policy_id: str,
    body: RejectRequest,
    user: dict = Depends(require_auditor),
):
    """
    Отклонить политику: pending_review → rejected.

    Доступно: admin, auditor.
    """
    try:
        reviewer = user.get("email", user.get("sub", "unknown"))
        record = _plm.reject(policy_id, reviewer=reviewer, reason=body.reason)
        return {"message": "Политика отклонена", "policy": _serialize(record)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/{policy_id}/revise")
async def revise_policy(
    policy_id: str,
    body: ReviseRequest,
    user: dict = Depends(require_auditor),
):
    """
    Переработать отклонённую политику: rejected → draft.

    Доступно: admin, auditor.
    """
    try:
        editor = user.get("email", user.get("sub", "unknown"))
        record = _plm.revise(policy_id, new_content=body.content, editor=editor)
        return {"message": "Политика переработана и возвращена в черновик", "policy": _serialize(record)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/{policy_id}")
async def delete_draft(
    policy_id: str,
    user: dict = Depends(require_admin),
):
    """
    Удалить черновик политики.

    Только admin. Можно удалять только draft (одобренные нельзя).
    """
    try:
        _plm.delete_draft(policy_id)
        return {"message": f"Черновик политики {policy_id} удалён"}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
