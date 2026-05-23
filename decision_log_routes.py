"""
Decision Log Routes — REST API для Explainability Layer.

Позволяет аудитору просматривать полный decision trace каждого AI-вызова.

Префикс: /api/ai-decisions
Auth: любой авторизованный пользователь (auditor, viewer, admin …)
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ai_decision_log import AIDecisionLogger, AIDecisionRecord, DecisionType, get_decision_logger
from log_config import get_logger

# Импортируем require_auth из ui_server через lazy import, чтобы избежать
# циклических зависимостей. ui_server регистрирует роутер и сам определяет
# require_auth — поэтому принимаем его как параметр зависимости стандартно.
# Для совместимости дублируем локальную версию аналогично gap_analysis_routes.py.
from fastapi import Cookie
from auth import decode_token

log = get_logger(__name__)

router = APIRouter(prefix="/api/ai-decisions", tags=["ai-decisions"])

# Используем глобальный синглтон — тот же экземпляр что у policy_agent и gap_analysis_agent
_logger = get_decision_logger()


# ── Auth dependency ────────────────────────────────────────────────────────────

def _require_auth(access_token: Optional[str] = Cookie(default=None)) -> dict:
    """Любой авторизованный пользователь — аудитор должен видеть traces."""
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(access_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalid or expired")
    return payload


# ── Утилиты ───────────────────────────────────────────────────────────────────

def _record_to_dict(rec: AIDecisionRecord) -> dict:
    """Сериализует AIDecisionRecord в dict для JSON-ответа."""
    d = asdict(rec)
    d["decision_type"] = rec.decision_type.value
    return d


# ── Эндпоинты ─────────────────────────────────────────────────────────────────

@router.get("", summary="Список AI-решений с опциональной фильтрацией")
async def list_decisions(
    type: Optional[str] = Query(default=None, description="Фильтр по типу: policy_generation | gap_analysis | control_assessment | risk_scoring | vendor_assessment"),
    control: Optional[str] = Query(default=None, description="Фильтр по коду контроля, например CC6.1"),
    limit: int = Query(default=50, ge=1, le=500, description="Максимум записей (1–500)"),
    user: dict = Depends(_require_auth),
) -> list[dict]:
    """
    Возвращает AI-решения от новых к старым.

    Доступна фильтрация по типу решения (`?type=gap_analysis`) и коду контроля
    (`?control=CC6.1`). Параметры можно комбинировать.
    """
    # Валидируем тип если передан
    if type is not None:
        valid_types = {dt.value for dt in DecisionType}
        if type not in valid_types:
            raise HTTPException(
                status_code=422,
                detail=f"Неверный тип '{type}'. Допустимые значения: {sorted(valid_types)}",
            )

    records = _logger.get_all(decision_type=type, control_id=control, limit=limit)
    return [_record_to_dict(r) for r in records]


@router.get("/stats", summary="Агрегированная статистика по AI-решениям")
async def get_stats(user: dict = Depends(_require_auth)) -> dict:
    """
    Возвращает статистику:
    - total — общее количество записей
    - by_type — распределение по типам решений
    - avg_confidence — средняя уверенность (0.0–1.0)
    - avg_duration_ms — среднее время вызова в мс
    - by_outcome — распределение по исходам (PASS/FAIL/draft …)
    """
    return _logger.get_stats()


@router.get("/control/{control_id}", summary="Все AI-решения по конкретному контролу")
async def decisions_for_control(
    control_id: str,
    user: dict = Depends(_require_auth),
) -> list[dict]:
    """
    Возвращает все решения для указанного контроля (например CC6.1),
    от новых к старым.
    """
    records = _logger.get_for_control(control_id)
    if not records:
        # Пустой список — не ошибка, контрол просто ещё не анализировался
        return []
    return [_record_to_dict(r) for r in records]


@router.get("/audit-trail/{control_id}", summary="Упрощённый audit trail для аудитора")
async def audit_trail(
    control_id: str,
    user: dict = Depends(_require_auth),
) -> list[dict]:
    """
    Упрощённый список для аудитора: date, model, outcome, confidence.

    Не содержит prompt_summary и output_summary — только достаточно для
    ответа на вопрос "что, когда и с каким результатом решил AI".
    """
    return _logger.get_audit_trail(control_id)


@router.get("/{decision_id}", summary="Одна AI-запись по UUID")
async def get_decision(
    decision_id: str,
    user: dict = Depends(_require_auth),
) -> dict:
    """
    Возвращает полную запись AI-решения по UUID.
    Содержит prompt_summary, output_summary, reasoning, confidence, metadata.
    """
    rec = _logger.get_by_id(decision_id)
    if not rec:
        raise HTTPException(status_code=404, detail=f"Decision {decision_id!r} не найдено")
    return _record_to_dict(rec)
