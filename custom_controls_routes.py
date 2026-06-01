import os
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import Optional, List
from auth import require_auth, require_admin, require_auditor
from custom_controls import CustomControlsManager
from evidence_client import EvidenceClient

router = APIRouter(prefix="/api/custom-controls", tags=["custom-controls"])
_manager = CustomControlsManager()

from config import get_settings as _get_settings
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", _get_settings().evidence_tracker_url)

@router.get("")
async def get_custom_controls(
    framework: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    payload: dict = Depends(require_auth)
):
    """Список кастомных контролей."""
    return _manager.get_all(framework=framework, status=status)

@router.get("/summary")
async def get_summary(payload: dict = Depends(require_auth)):
    """Статистика по кастомным контролям."""
    return _manager.get_summary()

@router.get("/templates")
async def get_templates(payload: dict = Depends(require_auth)):
    """Список шаблонов контролей."""
    return _manager.get_templates()

# Должен быть ДО /{control_id} — иначе FastAPI перехватит /all как control_id
@router.get("/all")
async def get_all_combined(payload: dict = Depends(require_auth)):
    from control_mapping import CONTROL_MAPPINGS
    from db_repository import ControlRepository
    from database import AsyncSessionLocal

    # Стандартные контроли через EvidenceClient (fallback уже встроен в get_controls())
    standard: list = []
    try:
        ec = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="custom_controls")
        result = ec.get_controls()
        if isinstance(result, list):
            standard = result
    except Exception:
        pass

    # Индекс для нормализации UUID-ключей Evidence Tracker → SOC2-коды
    soc2_by_description: dict = {m.description: m.soc2 for m in CONTROL_MAPPINGS}
    soc2_index: dict = {m.soc2: m for m in CONTROL_MAPPINGS}

    # DB-статусы — источник истины (сюда пишут агенты)
    db_statuses: dict = {}
    try:
        async with AsyncSessionLocal() as session:
            repo = ControlRepository(session)
            all_statuses = await repo.list_all()
            db_statuses = {cs.control_id: cs.status for cs in all_statuses}
    except Exception:
        pass

    if not standard:
        standard = [
            {
                "id": m.soc2,
                "code": m.soc2,
                "title": m.description,
                "description": m.description,
                "framework": "SOC2",
                "category": m.category,
                "status": db_statuses.get(m.soc2, "UNKNOWN"),
            }
            for m in CONTROL_MAPPINGS
        ]
    else:
        # Нормализуем UUID-ключи и подставляем DB-статусы
        for ctrl in standard:
            code = ctrl.get("code") or ctrl.get("id", "")
            if code not in soc2_index:
                title = ctrl.get("title", "") or ctrl.get("description", "")
                code = soc2_by_description.get(title, code)
                if code in soc2_index:
                    ctrl["code"] = code
                    ctrl["id"] = code
            if code in db_statuses:
                ctrl["status"] = db_statuses[code]

    return _manager.get_all_controls_combined(standard)

@router.get("/{control_id}")
async def get_control(control_id: str, payload: dict = Depends(require_auth)):
    """Детали одного контроля."""
    c = _manager.get_by_id(control_id)
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    return c

@router.post("")
async def create_control(data: dict, payload: dict = Depends(require_auditor)):
    """Создать новый контроль."""
    try:
        return _manager.create(data, payload.get("sub", "admin@marineso.com"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/from-template/{template_id}")
async def create_from_template(template_id: str, payload: dict = Depends(require_auditor)):
    """Создать контроль из шаблона."""
    try:
        return _manager.create_from_template(template_id, payload.get("sub", "admin@marineso.com"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/{control_id}")
async def update_control(control_id: str, data: dict, payload: dict = Depends(require_auditor)):
    """Обновить поля контроля."""
    c = _manager.update(control_id, data)
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    return c

@router.post("/{control_id}/status")
async def update_status(
    control_id: str, 
    status: str = Body(..., embed=True), 
    notes: str = Body("", embed=True),
    payload: dict = Depends(require_auditor)
):
    """Обновить статус контроля."""
    c = _manager.update_status(control_id, status, notes, payload.get("sub", "admin@marineso.com"))
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    return c

@router.delete("/{control_id}")
async def delete_control(control_id: str, payload: dict = Depends(require_admin)):
    """Удалить контроль."""
    success = _manager.delete(control_id)
    if not success:
        raise HTTPException(status_code=404, detail="Control not found")
    return {"status": "deleted"}

