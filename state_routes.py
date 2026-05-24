"""
state_routes.py — FastAPI роуты для ComplianceStateEngine.

Предоставляет REST API для получения авторитативного compliance-state.

Принципы:
  - GET-эндпоинты только читают (никогда не мутируют engine напрямую)
  - POST /recalculate — единственный мутирующий эндпоинт
  - Все ответы — детерминированные (не AI)
  - AI рекомендации — только через отдельный advisory endpoint
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from compliance_state_engine import (
    ComplianceStateEngine,
    ControlState,
    CompliancePosture,
    FailExplanation,
    get_state_engine,
)
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/state", tags=["compliance-state"])


# ── Pydantic request/response модели ──────────────────────────────────────────

class RecalculateRequest(BaseModel):
    """Тело запроса для POST /recalculate."""
    control_id: Optional[str] = None  # None = пересчитать все


class RecalculateResponse(BaseModel):
    ok: bool
    message: str
    control_id: Optional[str] = None


class RestoreRequest(BaseModel):
    """Тело запроса для POST /restore — snapshot dict."""
    snapshot: Dict[str, Any]


# ── Роуты ──────────────────────────────────────────────────────────────────────

@router.get(
    "/control/{control_id}",
    response_model=Dict[str, Any],
    summary="Полный state контроля",
    description=(
        "Возвращает авторитативное состояние контроля: статус, confidence, "
        "evidence, риски, фреймворки, причину статуса. "
        "Только deterministic logic — AI не используется."
    ),
)
async def get_control_state(control_id: str) -> Dict[str, Any]:
    """GET /api/state/control/{control_id}"""
    engine = get_state_engine()
    try:
        state: ControlState = engine.get_control_state(control_id)
        return state.to_dict()
    except Exception as exc:
        log.error("Ошибка получения state для %s: %s", control_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка получения состояния контроля: {exc}",
        ) from exc


@router.get(
    "/posture",
    response_model=Dict[str, Any],
    summary="Общая compliance posture",
    description=(
        "Возвращает взвешенный score, breakdown по категориям, "
        "список critical fails и общее количество evidence."
    ),
)
async def get_compliance_posture() -> Dict[str, Any]:
    """GET /api/state/posture"""
    engine = get_state_engine()
    try:
        posture: CompliancePosture = engine.get_full_compliance_posture()
        return posture.to_dict()
    except Exception as exc:
        log.error("Ошибка получения compliance posture: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка получения posture: {exc}",
        ) from exc


@router.get(
    "/explain/{control_id}",
    response_model=Dict[str, Any],
    summary="Объяснение FAIL-статуса контроля",
    description=(
        "Возвращает полное объяснение причины статуса: "
        "dependency chain, затронутые контроли, propagation рисков, "
        "SLA устранения, последние события."
    ),
)
async def explain_control_fail(control_id: str) -> Dict[str, Any]:
    """GET /api/state/explain/{control_id}"""
    engine = get_state_engine()
    try:
        explanation: FailExplanation = engine.explain_control_fail(control_id)
        return explanation.to_dict()
    except Exception as exc:
        log.error("Ошибка объяснения для %s: %s", control_id, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка получения объяснения: {exc}",
        ) from exc


@router.post(
    "/recalculate",
    response_model=RecalculateResponse,
    summary="Принудительный пересчёт compliance-state",
    description=(
        "Пересчитывает один контроль или все контроли (если control_id не задан). "
        "Публикует события через event_bus если статус изменился. "
        "Пересчёт выполняется в background task (non-blocking)."
    ),
)
async def recalculate(
    request: RecalculateRequest,
    background_tasks: BackgroundTasks,
) -> RecalculateResponse:
    """POST /api/state/recalculate"""
    engine = get_state_engine()
    control_id = request.control_id

    # Запускаем пересчёт в фоне (не блокируем HTTP)
    background_tasks.add_task(_run_recalculate, engine, control_id)

    if control_id:
        return RecalculateResponse(
            ok=True,
            message=f"Пересчёт контроля {control_id} запущен",
            control_id=control_id,
        )
    return RecalculateResponse(
        ok=True,
        message="Пересчёт всех контролей запущен",
        control_id=None,
    )


@router.get(
    "/snapshot",
    response_model=Dict[str, Any],
    summary="Полный snapshot compliance-state",
    description=(
        "Возвращает весь compliance state как JSON-serializable dict. "
        "Используется для time-machine и replay."
    ),
)
async def get_state_snapshot() -> Dict[str, Any]:
    """GET /api/state/snapshot"""
    engine = get_state_engine()
    try:
        return engine.get_state_snapshot()
    except Exception as exc:
        log.error("Ошибка получения snapshot: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка получения snapshot: {exc}",
        ) from exc


@router.post(
    "/restore",
    response_model=Dict[str, Any],
    summary="Восстановить state из snapshot",
    description=(
        "Применяет snapshot к ComplianceStateEngine. "
        "Публикует CONTROL_STATUS_CHANGED для изменившихся контролей."
    ),
)
async def restore_from_snapshot(request: RestoreRequest) -> Dict[str, Any]:
    """POST /api/state/restore"""
    engine = get_state_engine()
    snapshot = request.snapshot

    if not isinstance(snapshot, dict):
        raise HTTPException(
            status_code=422,
            detail="snapshot должен быть объектом (dict)",
        )

    try:
        engine.apply_snapshot(snapshot)
        controls_count = len(snapshot.get("controls", {}))
        return {
            "ok": True,
            "message": f"Snapshot восстановлен: {controls_count} контролей",
            "controls_loaded": controls_count,
            "snapshot_version": snapshot.get("version", "unknown"),
        }
    except Exception as exc:
        log.error("Ошибка восстановления snapshot: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка восстановления snapshot: {exc}",
        ) from exc


# ── Вспомогательные функции ────────────────────────────────────────────────────

def _run_recalculate(
    engine: ComplianceStateEngine,
    control_id: Optional[str],
) -> None:
    """Background task: запускает пересчёт."""
    try:
        engine.recalculate(control_id=control_id)
        if control_id:
            log.info("Пересчёт контроля %s завершён", control_id)
        else:
            log.info("Пересчёт всех контролей завершён")
    except Exception as exc:
        log.error("Ошибка в background recalculate: %s", exc)
