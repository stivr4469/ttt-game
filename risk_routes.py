import os
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional, List
from auth import require_auth, require_admin
from risk_register import RiskRegister
from evidence_client import EvidenceClient

router = APIRouter(prefix="/api/risks", tags=["risk-register"])

# Алиас-роутер для совместимости с /api/risk-register
router_alias = APIRouter(prefix="/api/risk-register", tags=["risk-register"])
_register = RiskRegister()

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")

@router.get("")
async def get_risks(
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    payload: dict = Depends(require_auth)
):
    """Возвращает все риски с возможностью фильтрации."""
    return _register.get_all(status=status, category=category)

@router.get("/summary")
async def get_risk_summary(payload: dict = Depends(require_auth)):
    """Возвращает статистику по рискам."""
    return _register.get_summary()

@router.get("/matrix")
async def get_risk_matrix(payload: dict = Depends(require_auth)):
    """Возвращает данные для матрицы рисков."""
    return _register.get_risk_matrix()

@router.get("/{risk_id}")
async def get_risk(risk_id: str, payload: dict = Depends(require_auth)):
    """Возвращает детали одного риска."""
    risk = _register.get_by_id(risk_id)
    if not risk:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    return risk

@router.post("")
async def create_risk(data: dict, payload: dict = Depends(require_auth)):
    """Создает риск вручную. Требует Admin или Auditor."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return _register.create(data)

@router.patch("/{risk_id}")
async def update_risk(risk_id: str, data: dict, payload: dict = Depends(require_auth)):
    """Обновляет риск. Требует Admin или Auditor."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    
    risk = _register.update(risk_id, data)
    if not risk:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    return risk

@router.delete("/{risk_id}")
async def delete_risk(risk_id: str, payload: dict = Depends(require_admin)):
    """Удаляет риск. Только для Admin."""
    success = _register.delete(risk_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Risk {risk_id} not found")
    return {"status": "deleted"}

@router.post("/sync")
async def sync_risks(payload: dict = Depends(require_admin)):
    """Синхронизирует риски из FAIL-контролей."""
    ec = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="risk_register")
    try:
        controls = ec.get_controls()
        return _register.sync_from_controls(controls)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to fetch controls: {str(e)}")


# ── Алиасы /api/risk-register/* → /api/risks/* ─────────────────────────────

@router_alias.get("")
async def get_risks_alias(
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    payload: dict = Depends(require_auth)
):
    """Алиас: GET /api/risk-register → /api/risks."""
    return _register.get_all(status=status, category=category)


@router_alias.get("/summary")
async def get_risk_summary_alias(payload: dict = Depends(require_auth)):
    """Алиас: GET /api/risk-register/summary → /api/risks/summary."""
    return _register.get_summary()


@router_alias.get("/matrix")
async def get_risk_matrix_alias(payload: dict = Depends(require_auth)):
    """Алиас: GET /api/risk-register/matrix → /api/risks/matrix."""
    return _register.get_risk_matrix()
