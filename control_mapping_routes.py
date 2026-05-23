"""
Роутер: /api/control-mapping

Endpoints:
  GET  /api/control-mapping                    — все маппинги
  GET  /api/control-mapping/coverage           — отчёт покрытия
  GET  /api/control-mapping/search?q=AC-2      — поиск по любому ID
  GET  /api/control-mapping/frameworks         — поддерживаемые фреймворки
  GET  /api/control-mapping/soc2/{control_id}  — маппинг SOC 2 контроля
  GET  /api/control-mapping/iso/{iso_id}       — SOC 2 контролы для ISO ID
  GET  /api/control-mapping/nist/{nist_id}     — SOC 2 контролы для NIST ID
"""

from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from auth import require_auth
from control_mapping import ControlMappingEngine, FrameworkMapping, get_engine

router = APIRouter(prefix="/api/control-mapping", tags=["control-mapping"])


# ── Вспомогательная функция сериализации ────────────────────────────────────

def _mapping_to_dict(m: FrameworkMapping) -> dict:
    """Сериализовать frozen dataclass в dict (asdict безопасен для frozen)."""
    return asdict(m)


# ── Endpoints (неизменяемые данные → GET-only, без кешей) ─────────────────────

@router.get("")
async def get_all_mappings(
    category: Optional[str] = Query(None, description="Фильтр по категории TSC (CC1, CC6, A, PI, C, P)"),
    payload: dict = Depends(require_auth),
) -> list[dict]:
    """Все маппинги контролей. Опционально — фильтр по категории TSC."""
    engine: ControlMappingEngine = get_engine()
    mappings = engine.get_all_mappings()
    if category:
        cat_upper = category.upper()
        mappings = [m for m in mappings if m.category.upper() == cat_upper]
    return [_mapping_to_dict(m) for m in mappings]


@router.get("/coverage")
async def get_coverage(
    payload: dict = Depends(require_auth),
) -> dict:
    """Отчёт покрытия: % SOC 2 контролей с маппингом в каждом фреймворке."""
    return get_engine().get_coverage_report()


@router.get("/frameworks")
async def get_frameworks(
    payload: dict = Depends(require_auth),
) -> list[dict]:
    """Список поддерживаемых фреймворков с мета-информацией."""
    return get_engine().get_supported_frameworks()


@router.get("/search")
async def search_mappings(
    q: str = Query(..., min_length=1, description="Поисковый запрос: любой ID или текст описания"),
    payload: dict = Depends(require_auth),
) -> dict:
    """Поиск маппингов по любому ID (CC6.1, AC-2, A.5.15, 6.1) или ключевому слову."""
    if not q.strip():
        raise HTTPException(status_code=400, detail="Search query cannot be empty")
    engine: ControlMappingEngine = get_engine()
    results = engine.search(q.strip())
    return {
        "query": q.strip(),
        "total": len(results),
        "results": [_mapping_to_dict(m) for m in results],
    }


@router.get("/soc2/{control_id}")
async def get_soc2_mapping(
    control_id: str,
    payload: dict = Depends(require_auth),
) -> dict:
    """Маппинг для конкретного SOC 2 контроля (например CC6.1, A1.2, PI1.1)."""
    # Нормализуем: "cc6.1" → "CC6.1"
    normalized = control_id.upper()
    mapping = get_engine().get_mappings_for_control(normalized)
    if mapping is None:
        raise HTTPException(
            status_code=404,
            detail=f"SOC 2 control '{control_id}' not found. "
                   f"Available controls: CC1.1–CC9.2, A1.1–A1.3, PI1.1, C1.1–C1.2, P1.1",
        )
    return _mapping_to_dict(mapping)


@router.get("/iso/{iso_id:path}")
async def get_iso_mapping(
    iso_id: str,
    payload: dict = Depends(require_auth),
) -> dict:
    """SOC 2 контролы, покрываемые указанным ISO 27001 контролем (например A.5.15)."""
    # Нормализуем: "a.5.15" → "A.5.15"
    normalized = iso_id.upper()
    engine: ControlMappingEngine = get_engine()
    soc2_ids = engine.get_soc2_for_iso(normalized)
    if not soc2_ids:
        raise HTTPException(
            status_code=404,
            detail=f"ISO 27001 control '{iso_id}' not found in mappings",
        )
    return {
        "iso_id": normalized,
        "soc2_controls": soc2_ids,
        "count": len(soc2_ids),
        "details": [
            _mapping_to_dict(engine.get_mappings_for_control(sid))
            for sid in soc2_ids
            if engine.get_mappings_for_control(sid) is not None
        ],
    }


@router.get("/nist/{nist_id}")
async def get_nist_mapping(
    nist_id: str,
    payload: dict = Depends(require_auth),
) -> dict:
    """SOC 2 контролы, покрываемые указанным NIST 800-53 контролем (например AC-2)."""
    normalized = nist_id.upper()
    engine: ControlMappingEngine = get_engine()
    soc2_ids = engine.get_soc2_for_nist(normalized)
    if not soc2_ids:
        raise HTTPException(
            status_code=404,
            detail=f"NIST 800-53 control '{nist_id}' not found in mappings",
        )
    return {
        "nist_id": normalized,
        "soc2_controls": soc2_ids,
        "count": len(soc2_ids),
        "details": [
            _mapping_to_dict(engine.get_mappings_for_control(sid))
            for sid in soc2_ids
            if engine.get_mappings_for_control(sid) is not None
        ],
    }
