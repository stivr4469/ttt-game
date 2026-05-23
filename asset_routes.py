"""
asset_routes.py — FastAPI роутер для Asset-centric compliance API.

Все эндпоинты требуют аутентификации.
Операции создания/удаления требуют роль admin.

Маршруты:
  GET  /api/assets              — список активов (фильтры: ?type=&criticality=&environment=)
  POST /api/assets              — создать актив
  GET  /api/assets/stats        — статистика по активам
  POST /api/assets/sync         — синхронизировать из MDM + Scanner
  GET  /api/assets/non-compliant — все non-compliant активы
  GET  /api/assets/{asset_id}           — детали актива
  PUT  /api/assets/{asset_id}           — обновить актив
  DELETE /api/assets/{asset_id}         — удалить актив
  GET  /api/assets/{asset_id}/compliance — compliance posture
  GET  /api/assets/{asset_id}/controls  — применимые контроли
  GET  /api/assets/{asset_id}/risks     — связанные риски
  POST /api/assets/{asset_id}/controls  — добавить/обновить маппинг на контроль
  POST /api/assets/{asset_id}/risks     — добавить/обновить маппинг на риск
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, validator

from asset_manager import (
    ASSET_TYPES,
    COMPLIANCE_STATUSES,
    CRITICALITY_ORDER,
    ENVIRONMENTS,
    EXPOSURE_LEVELS,
    AssetManager,
    get_asset_manager,
)
from auth import require_auth, require_admin

# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/assets", tags=["assets"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class AssetCreateRequest(BaseModel):
    """Схема для создания нового актива."""

    asset_type: str = Field(..., description="Тип: device/cloud_account/repository/database/employee/vendor_service")
    name: str = Field(..., min_length=1, max_length=300, description="Название актива")
    owner_id: Optional[str] = Field(None, max_length=200, description="Email или ID владельца")
    environment: str = Field("prod", description="Окружение: prod/staging/dev")
    criticality: str = Field("medium", description="Критичность: critical/high/medium/low")
    tags: Dict[str, Any] = Field(default_factory=dict, description="Произвольные теги")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Специфичные метаданные")

    @validator("asset_type")
    def validate_type(cls, v: str) -> str:
        if v not in ASSET_TYPES:
            raise ValueError(f"Недопустимый тип '{v}'. Допустимые: {sorted(ASSET_TYPES)}")
        return v

    @validator("criticality")
    def validate_criticality(cls, v: str) -> str:
        if v not in CRITICALITY_ORDER:
            raise ValueError(f"Недопустимая критичность '{v}'")
        return v

    @validator("environment")
    def validate_env(cls, v: str) -> str:
        if v not in ENVIRONMENTS:
            raise ValueError(f"Недопустимое окружение '{v}'. Допустимые: {sorted(ENVIRONMENTS)}")
        return v


class AssetUpdateRequest(BaseModel):
    """Схема для частичного обновления актива."""

    name: Optional[str] = Field(None, min_length=1, max_length=300)
    owner_id: Optional[str] = Field(None, max_length=200)
    environment: Optional[str] = None
    criticality: Optional[str] = None
    tags: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    @validator("criticality", pre=True, always=True)
    def validate_criticality(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in CRITICALITY_ORDER:
            raise ValueError(f"Недопустимая критичность '{v}'")
        return v

    @validator("environment", pre=True, always=True)
    def validate_env(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ENVIRONMENTS:
            raise ValueError(f"Недопустимое окружение '{v}'")
        return v


class ComplianceMappingRequest(BaseModel):
    """Схема для добавления/обновления маппинга актив ↔ контроль."""

    control_id: str = Field(..., min_length=1, max_length=50, description="ID контроля, например CC6.6")
    status: str = Field(..., description="PASS / FAIL / PARTIAL / UNKNOWN")
    evidence_ids: List[str] = Field(default_factory=list, description="Список ID доказательств")

    @validator("status")
    def validate_status(cls, v: str) -> str:
        if v not in COMPLIANCE_STATUSES:
            raise ValueError(f"Недопустимый статус '{v}'. Допустимые: {sorted(COMPLIANCE_STATUSES)}")
        return v


class RiskMappingRequest(BaseModel):
    """Схема для добавления/обновления маппинга актив ↔ риск."""

    risk_id: str = Field(..., min_length=1, max_length=50, description="ID риска, например RISK-001")
    exposure_level: str = Field("medium", description="Уровень экспозиции: critical/high/medium/low")

    @validator("exposure_level")
    def validate_exposure(cls, v: str) -> str:
        if v not in EXPOSURE_LEVELS:
            raise ValueError(f"Недопустимый exposure_level '{v}'")
        return v


# ── Dependency: получение менеджера ──────────────────────────────────────────

def _get_manager() -> AssetManager:
    """FastAPI dependency: возвращает глобальный AssetManager."""
    return get_asset_manager()


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
async def list_assets(
    type: Optional[str] = Query(None, alias="type", description="Фильтр по типу актива"),
    criticality: Optional[str] = Query(None, description="Фильтр по критичности"),
    environment: Optional[str] = Query(None, description="Фильтр по окружению"),
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Возвращает список активов с опциональными фильтрами.

    Query params:
      ?type=device           — фильтр по типу
      ?criticality=critical  — фильтр по критичности
      ?environment=prod      — фильтр по окружению
    """
    # Валидируем фильтры
    if type and type not in ASSET_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Недопустимый тип '{type}'. Допустимые: {sorted(ASSET_TYPES)}",
        )
    if criticality and criticality not in CRITICALITY_ORDER:
        raise HTTPException(
            status_code=400,
            detail=f"Недопустимая критичность '{criticality}'",
        )
    if environment and environment not in ENVIRONMENTS:
        raise HTTPException(
            status_code=400,
            detail=f"Недопустимое окружение '{environment}'",
        )

    assets = manager.list_assets(
        asset_type=type,
        criticality=criticality,
        environment=environment,
    )
    return {"items": assets, "total": len(assets)}


@router.post("", status_code=201)
async def create_asset(
    body: AssetCreateRequest,
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Регистрирует новый актив.

    Требует роль admin или auditor.
    """
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Требуется роль admin или auditor")

    try:
        # .model_dump() — Pydantic v2; .dict() — v1 (backward compat alias)
        data = body.model_dump() if hasattr(body, "model_dump") else body.dict()
        asset = manager.register_asset(data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return asset


@router.get("/stats")
async def get_stats(
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Возвращает сводную статистику по активам.

    Включает: количество по типам, критичности, окружению,
    суммарный compliance % по всем маппингам.
    """
    return manager.get_stats()


@router.post("/sync")
async def sync_assets(
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Синхронизирует активы из внешних источников:
      - MDM inventory (mdm_device_inventory.json)
      - Scanner evidence (AWS ресурсы)

    Требует роль admin или scanner.
    """
    if payload.get("role") not in ("admin", "scanner"):
        raise HTTPException(status_code=403, detail="Требуется роль admin или scanner")

    mdm_result = manager.sync_from_mdm()
    scanner_result = manager.sync_from_scanner()

    return {
        "mdm": mdm_result,
        "scanner": scanner_result,
        "total_created": mdm_result.get("created", 0) + scanner_result.get("created", 0),
        "total_updated": mdm_result.get("updated", 0) + scanner_result.get("updated", 0),
    }


@router.get("/non-compliant")
async def get_non_compliant(
    control_id: Optional[str] = Query(None, description="Фильтр по конкретному контролю"),
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Возвращает все активы со статусом FAIL.

    Query params:
      ?control_id=CC6.6 — фильтровать по контролю
    """
    results = manager.find_non_compliant_assets(control_id=control_id)
    return {
        "items": results,
        "total": len(results),
        "control_id_filter": control_id,
    }


@router.get("/{asset_id}")
async def get_asset(
    asset_id: str,
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Возвращает детали актива по ID."""
    asset = manager.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Актив {asset_id!r} не найден")
    return asset


@router.put("/{asset_id}")
async def update_asset(
    asset_id: str,
    body: AssetUpdateRequest,
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Частично обновляет актив.

    Требует роль admin или auditor.
    """
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Требуется роль admin или auditor")

    # Фильтруем None-поля чтобы не затирать существующие значения
    raw = body.model_dump() if hasattr(body, "model_dump") else body.dict()
    update_data = {k: v for k, v in raw.items() if v is not None}

    if not update_data:
        raise HTTPException(status_code=400, detail="Нет полей для обновления")

    try:
        updated = manager.update_asset(asset_id, update_data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if not updated:
        raise HTTPException(status_code=404, detail=f"Актив {asset_id!r} не найден")

    return updated


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(
    asset_id: str,
    payload: dict = Depends(require_admin),
    manager: AssetManager = Depends(_get_manager),
) -> None:
    """
    Удаляет актив и все связанные маппинги.

    Требует роль admin.
    """
    deleted = manager.delete_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Актив {asset_id!r} не найден")


@router.get("/{asset_id}/compliance")
async def get_asset_compliance(
    asset_id: str,
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Возвращает compliance posture для актива.

    Включает: % PASS, количество по статусам, список всех контролей.
    """
    asset = manager.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Актив {asset_id!r} не найден")

    return manager.get_asset_compliance_posture(asset_id)


@router.get("/{asset_id}/controls")
async def get_asset_controls(
    asset_id: str,
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Возвращает список контролей, применимых к данному активу.
    """
    asset = manager.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Актив {asset_id!r} не найден")

    controls = manager.get_controls_for_asset(asset_id)
    return {"asset_id": asset_id, "controls": controls, "total": len(controls)}


@router.post("/{asset_id}/controls", status_code=201)
async def add_control_mapping(
    asset_id: str,
    body: ComplianceMappingRequest,
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Добавляет или обновляет маппинг актива на контроль.

    Требует роль admin, auditor или scanner.
    """
    if payload.get("role") not in ("admin", "auditor", "scanner"):
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    try:
        mapping = manager.update_compliance_status(
            asset_id=asset_id,
            control_id=body.control_id,
            status=body.status,
            evidence_ids=body.evidence_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if mapping is None:
        raise HTTPException(status_code=404, detail=f"Актив {asset_id!r} не найден")

    return mapping


@router.get("/{asset_id}/risks")
async def get_asset_risks(
    asset_id: str,
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Возвращает риски, связанные с данным активом."""
    asset = manager.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Актив {asset_id!r} не найден")

    risks = manager.get_risk_mappings(asset_id)
    return {"asset_id": asset_id, "risks": risks, "total": len(risks)}


@router.post("/{asset_id}/risks", status_code=201)
async def add_risk_mapping(
    asset_id: str,
    body: RiskMappingRequest,
    payload: dict = Depends(require_auth),
    manager: AssetManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """
    Добавляет или обновляет маппинг актива на риск.

    Требует роль admin или auditor.
    """
    if payload.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Требуется роль admin или auditor")

    try:
        mapping = manager.add_risk_mapping(
            asset_id=asset_id,
            risk_id=body.risk_id,
            exposure_level=body.exposure_level,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if mapping is None:
        raise HTTPException(status_code=404, detail=f"Актив {asset_id!r} не найден")

    return mapping
