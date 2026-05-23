"""
FastAPI роутер для Audit Timeline & Scoping Wizard.
Паттерн аналогичен auditor_routes.py.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, Header, Cookie, Depends
from pydantic import BaseModel

from audit_timeline import AuditTimeline, SCOPE_SYSTEMS
from auth import decode_token, ROLES
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/audit-timeline", tags=["audit-timeline"])

# Единственный экземпляр менеджера для всего модуля
_timeline_mgr = AuditTimeline()


# ── Pydantic модели ──────────────────────────────────────────────────────────

class ScopeBody(BaseModel):
    systems: list[str] = []
    in_scope_controls: list[str] = []
    excluded: list[str] = []


class CreateTimelineBody(BaseModel):
    audit_date: str                 # "2026-09-01"
    framework: str = "soc2_type2"  # "soc2_type2" | "soc2_type1"
    scope: ScopeBody = ScopeBody()


class UpdateMilestoneBody(BaseModel):
    status: str   # not_started | in_progress | completed | blocked
    notes: str = ""


# ── Вспомогательные функции ──────────────────────────────────────────────────

def _get_current_user(
    authorization: Optional[str] = None,
    access_token: Optional[str] = None,
) -> Optional[dict]:
    """Декодирует JWT из заголовка Authorization: Bearer <token> или из cookie."""
    # Сначала пробуем cookie
    if access_token:
        return decode_token(access_token)
    # Затем Bearer header
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        return decode_token(token)
    return None


def _require_auth(
    authorization: Optional[str] = Header(default=None),
    access_token: Optional[str] = Cookie(default=None),
) -> dict:
    """Требует любого авторизованного пользователя (Bearer header или cookie)."""
    user = _get_current_user(authorization, access_token)
    if not user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    return user


def _require_roles_dep(allowed_roles: list[str]):
    """Фабрика Depends для проверки ролей."""
    def _check(user: dict = Depends(_require_auth)) -> dict:
        if user.get("role") not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Доступ запрещён. Требуются роли: {allowed_roles}",
            )
        return user
    return _check


# ── Эндпоинты ────────────────────────────────────────────────────────────────

@router.get("")
async def get_current_timeline_status(
    user: dict = Depends(_require_auth),
):
    """
    Текущий статус активного timeline.
    Доступно для любого авторизованного пользователя.
    """
    status = _timeline_mgr.get_current_status()
    return status


@router.get("/all")
async def get_all_timelines(
    user: dict = Depends(_require_roles_dep(["admin", "auditor"])),
):
    """
    Все timelines (активные и архивные).
    Доступно для Admin и Auditor.
    """
    timelines = _timeline_mgr.get_all_timelines()
    # Возвращаем без деталей milestones для списка
    return [
        {
            "id": tl["id"],
            "audit_date": tl["audit_date"],
            "framework": tl["framework"],
            "status": tl["status"],
            "created_by": tl["created_by"],
            "created_at": tl["created_at"],
            "milestones_count": len(tl.get("milestones", [])),
        }
        for tl in timelines
    ]


@router.get("/wizard/systems")
async def get_scope_systems(
    user: dict = Depends(_require_roles_dep(["admin"])),
):
    """
    Список систем для мастера определения области.
    Используется на шаге 3 Wizard.
    Доступно для Admin.
    """
    return SCOPE_SYSTEMS


@router.post("")
async def create_timeline(
    body: CreateTimelineBody,
    user: dict = Depends(_require_roles_dep(["admin"])),
):
    """
    Создаёт новый audit timeline.
    Предыдущий активный timeline переводится в archived.
    Доступно для Admin.
    """
    try:
        timeline = _timeline_mgr.create_timeline(
            audit_date=body.audit_date,
            framework=body.framework,
            scope=body.scope.model_dump(),
            created_by=user.get("email", "unknown"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    log.info(
        "Timeline создан через API",
        extra={"created_by": user.get("email"), "framework": body.framework},
    )
    return timeline


@router.get("/{timeline_id}")
async def get_timeline(
    timeline_id: str,
    user: dict = Depends(_require_auth),
):
    """
    Конкретный timeline с полным списком milestones.
    Доступно для любого авторизованного пользователя.
    """
    tl = _timeline_mgr.get_timeline_by_id(timeline_id)
    if not tl:
        raise HTTPException(status_code=404, detail=f"Timeline {timeline_id} не найден")
    return tl


@router.patch("/{timeline_id}/milestones/{milestone_id}")
async def update_milestone(
    timeline_id: str,
    milestone_id: str,
    body: UpdateMilestoneBody,
    user: dict = Depends(_require_roles_dep(["admin", "auditor"])),
):
    """
    Обновляет статус и заметки milestone.
    Доступно для Admin и Auditor.
    """
    try:
        updated = _timeline_mgr.update_milestone_status(
            timeline_id=timeline_id,
            milestone_id=milestone_id,
            status=body.status,
            notes=body.notes,
            updated_by=user.get("email", "unknown"),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    log.info(
        "Milestone обновлён через API",
        extra={"milestone": updated["name"], "status": body.status, "by": user.get("email")},
    )
    return updated


@router.get("/{timeline_id}/checklist")
async def get_timeline_checklist(
    timeline_id: str,
    user: dict = Depends(_require_roles_dep(["admin", "auditor"])),
):
    """
    Детальный чеклист задач для всего timeline.
    Доступно для Admin и Auditor.
    """
    try:
        checklist = _timeline_mgr.generate_checklist(timeline_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return checklist
