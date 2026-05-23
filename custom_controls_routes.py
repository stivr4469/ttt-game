import os
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from typing import Optional, List
from auth import require_auth, require_admin
from custom_controls import CustomControlsManager
from evidence_client import EvidenceClient

router = APIRouter(prefix="/api/custom-controls", tags=["custom-controls"])
_manager = CustomControlsManager()

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")

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
    ec = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="custom_controls")
    standard = ec.get_controls()
    return _manager.get_all_controls_combined(standard)

@router.get("/{control_id}")
async def get_control(control_id: str, payload: dict = Depends(require_auth)):
    """Детали одного контроля."""
    c = _manager.get_by_id(control_id)
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    return c

@router.post("")
async def create_control(data: dict, payload: dict = Depends(require_auth)):
    """Создать новый контроль."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    try:
        return _manager.create(data, payload.get("sub", "admin@marineso.com"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/from-template/{template_id}")
async def create_from_template(template_id: str, payload: dict = Depends(require_auth)):
    """Создать контроль из шаблона."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    try:
        return _manager.create_from_template(template_id, payload.get("sub", "admin@marineso.com"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.patch("/{control_id}")
async def update_control(control_id: str, data: dict, payload: dict = Depends(require_auth)):
    """Обновить поля контроля."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    c = _manager.update(control_id, data)
    if not c:
        raise HTTPException(status_code=404, detail="Control not found")
    return c

@router.post("/{control_id}/status")
async def update_status(
    control_id: str, 
    status: str = Body(..., embed=True), 
    notes: str = Body("", embed=True),
    payload: dict = Depends(require_auth)
):
    """Обновить статус контроля."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
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

