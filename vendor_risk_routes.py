"""
Vendor Risk Management Routes — FastAPI роутер.

Префикс: /api/vendors

Эндпоинты:
  GET    /api/vendors                    — список вендоров (фильтры: category, status, criticality)
  GET    /api/vendors/summary            — статистика
  GET    /api/vendors/subprocessors      — список субпроцессоров для Trust Center
  GET    /api/vendors/expiring-dpas      — DPA истекающие через N дней (default 30)
  GET    /api/vendors/{id}               — один вендор
  POST   /api/vendors                    — создать (admin/auditor)
  PATCH  /api/vendors/{id}               — обновить (admin/auditor)
  DELETE /api/vendors/{id}               — удалить (только admin)
  POST   /api/vendors/{id}/assess        — AI-оценка SOC2 отчёта
  GET    /api/vendors/{id}/assessments   — история оценок вендора
  POST   /api/vendors/{id}/renew-dpa     — обновить DPA expiry date
"""

from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from auth import require_auth, require_admin
from vendor_risk_agent import VendorRiskAgent

router = APIRouter(prefix="/api/vendors", tags=["vendor-risk"])

# Синглтон агента — создаётся один раз при импорте модуля
_agent = VendorRiskAgent()


# ── Утилиты ───────────────────────────────────────────────────────────────────

def _require_write(payload: dict) -> dict:
    """Admin или Auditor могут писать."""
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Admin or Auditor role required")
    return payload


# ── Статические маршруты (ВАЖНО: идут ДО /{id}) ──────────────────────────────

@router.get("/summary")
async def get_vendor_summary(payload: dict = Depends(require_auth)):
    """Статистика вендоров: по criticality, статусам, avg risk score."""
    return _agent.get_risk_summary()


@router.get("/subprocessors")
async def get_subprocessors(payload: dict = Depends(require_auth)):
    """
    Список субпроцессоров всех approved вендоров.
    Используется Trust Center для публикации.
    """
    return _agent.get_subprocessors_list()


@router.get("/expiring-dpas")
async def get_expiring_dpas(
    days: int = Query(default=30, ge=1, le=365, description="Горизонт в днях"),
    payload: dict = Depends(require_auth),
):
    """DPA, истекающие в течение указанного числа дней (default: 30)."""
    vendors = _agent.get_expiring_dpas(days=days)
    return [asdict(v) for v in vendors]


# ── Список вендоров ───────────────────────────────────────────────────────────

@router.get("")
async def get_vendors(
    category: Optional[str] = Query(None, description="Фильтр по категории"),
    status: Optional[str] = Query(None, description="Фильтр по статусу"),
    criticality: Optional[str] = Query(None, description="Фильтр по критичности"),
    payload: dict = Depends(require_auth),
):
    """Список вендоров с опциональной фильтрацией."""
    vendors = _agent.get_all_vendors(
        category=category,
        status=status,
        criticality=criticality,
    )
    return [asdict(v) for v in vendors]


# ── Один вендор ───────────────────────────────────────────────────────────────

@router.get("/{vendor_id}")
async def get_vendor(vendor_id: str, payload: dict = Depends(require_auth)):
    """Детали одного вендора."""
    vendor = _agent.get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} not found")
    return asdict(vendor)


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.post("")
async def create_vendor(data: dict, payload: dict = Depends(require_auth)):
    """
    Создаёт нового вендора.
    Требует: Admin или Auditor.
    """
    _require_write(payload)
    if not data.get("name"):
        raise HTTPException(status_code=422, detail="Поле 'name' обязательно")
    vendor = _agent.create_vendor(data)
    return asdict(vendor)


@router.patch("/{vendor_id}")
async def update_vendor(
    vendor_id: str,
    data: dict,
    payload: dict = Depends(require_auth),
):
    """
    Обновляет поля вендора.
    Требует: Admin или Auditor.
    """
    _require_write(payload)
    vendor = _agent.update_vendor(vendor_id, data)
    if vendor is None:
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} not found")
    return asdict(vendor)


@router.delete("/{vendor_id}")
async def delete_vendor(vendor_id: str, payload: dict = Depends(require_admin)):
    """Удаляет вендора. Только Admin."""
    success = _agent.delete_vendor(vendor_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} not found")
    return {"status": "deleted", "vendor_id": vendor_id}


# ── Assessments ───────────────────────────────────────────────────────────────

@router.post("/{vendor_id}/assess")
async def assess_vendor(
    vendor_id: str,
    body: dict,
    payload: dict = Depends(require_auth),
):
    """
    Запускает AI-оценку SOC2 отчёта вендора.

    Body:
      report_text: str  — текст или выдержка из SOC2 отчёта

    При отсутствии AI-ключей возвращает mock-оценку (не падает с ошибкой).
    Требует: Admin или Auditor.
    """
    _require_write(payload)

    report_text = body.get("report_text", "")
    if not report_text:
        raise HTTPException(status_code=422, detail="Поле 'report_text' обязательно")

    try:
        assessment = _agent.run_assessment(vendor_id, report_text)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Assessment failed: {exc}")

    return asdict(assessment)


@router.get("/{vendor_id}/assessments")
async def get_vendor_assessments(
    vendor_id: str,
    payload: dict = Depends(require_auth),
):
    """История оценок вендора (от новых к старым)."""
    vendor = _agent.get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} not found")

    assessments = _agent.get_assessments(vendor_id)
    return [asdict(a) for a in assessments]


# ── DPA management ────────────────────────────────────────────────────────────

@router.post("/{vendor_id}/renew-dpa")
async def renew_dpa(
    vendor_id: str,
    body: dict,
    payload: dict = Depends(require_auth),
):
    """
    Обновляет DPA expiry date вендора.

    Body:
      new_expiry: str  — новая дата истечения в формате YYYY-MM-DD

    Требует: Admin или Auditor.
    """
    _require_write(payload)

    new_expiry = body.get("new_expiry", "")
    if not new_expiry:
        raise HTTPException(status_code=422, detail="Поле 'new_expiry' обязательно (YYYY-MM-DD)")

    try:
        vendor = _agent.renew_dpa(vendor_id, new_expiry)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if vendor is None:
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} not found")

    return asdict(vendor)


@router.post("/{vendor_id}/jira-ticket")
async def create_jira_ticket(
    vendor_id: str,
    payload: dict = Depends(require_auth),
):
    """
    Создаёт Jira-тикет для вендора.

    При отсутствии Jira credentials возвращает mock-тикет.
    Требует: Admin или Auditor.
    """
    _require_write(payload)

    vendor = _agent.get_vendor(vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail=f"Vendor {vendor_id} not found")

    try:
        result = _agent.create_jira_ticket(vendor_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Jira ticket creation failed: {exc}")

    return result
