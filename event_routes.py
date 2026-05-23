"""
event_routes.py — FastAPI роуты для Compliance Event Bus.

Эндпоинты:
  GET  /api/events           — история событий (фильтры: entity_id, type, limit)
  GET  /api/events/stats     — статистика по типам за 24h/7d/30d
  POST /api/events/replay    — replay событий из AuditEventRepository за период

Все эндпоинты требуют авторизации (токен из auth.py).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from event_bus import ComplianceEventType, get_event_bus
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(tags=["events"])

# Максимум событий при поиске по event_id (ищем только в памяти)
_MAX_HISTORY_SEARCH = 1000


# ── Pydantic-модели ────────────────────────────────────────────────────────────

class ReplayRequest(BaseModel):
    """Параметры для replay событий из AuditEventRepository."""
    from_date: datetime   # начало периода (ISO 8601, с timezone)
    to_date:   datetime   # конец периода


class EventResponse(BaseModel):
    """Одно событие в ответе API."""
    event_id:    str
    event_type:  str
    entity_type: str
    entity_id:   str
    actor:       str
    payload:     Dict[str, Any]
    timestamp:   str
    severity:    str


class StatsResponse(BaseModel):
    """Статистика событий за период."""
    period:      str           # "24h" | "7d" | "30d"
    total:       int
    by_type:     Dict[str, int]
    by_severity: Dict[str, int]


class ReplayResponse(BaseModel):
    """Ответ на replay-запрос."""
    replayed:    int           # количество реплеированных событий
    from_date:   str
    to_date:     str
    events:      List[Dict[str, Any]]


# ── Вспомогательные функции ────────────────────────────────────────────────────

def _resolve_period_since(period: str) -> datetime:
    """
    Конвертирует строку периода в datetime UTC.

    Поддерживаемые значения: "24h", "7d", "30d"
    """
    now = datetime.now(timezone.utc)
    period_map = {
        "24h": timedelta(hours=24),
        "7d":  timedelta(days=7),
        "30d": timedelta(days=30),
    }
    delta = period_map.get(period)
    if delta is None:
        raise HTTPException(
            status_code=400,
            detail=f"Неверный период '{period}'. Допустимые значения: 24h, 7d, 30d",
        )
    return now - delta


# ── Роуты ──────────────────────────────────────────────────────────────────────

@router.get("/api/events", response_model=List[EventResponse])
async def list_events(
    entity_id:  Optional[str] = Query(None, description="Фильтр по entity_id"),
    type:       Optional[str] = Query(None, description="Фильтр по event_type"),
    severity:   Optional[str] = Query(None, description="Фильтр: info | warning | critical"),
    limit:      int            = Query(50, ge=1, le=500, description="Максимальное кол-во событий"),
) -> List[EventResponse]:
    """
    Возвращает историю compliance-событий из памяти EventBus.

    Параметры:
      entity_id — фильтр по конкретной сущности (control_id, policy_id, etc.)
      type      — фильтр по типу события (например "control.status_changed")
      severity  — фильтр по уровню: info / warning / critical
      limit     — максимум событий в ответе (1–500)
    """
    bus = get_event_bus()

    # Конвертируем строку типа в ComplianceEventType
    event_type_filter: Optional[ComplianceEventType] = None
    if type:
        try:
            event_type_filter = ComplianceEventType(type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Неизвестный тип события: '{type}'. "
                       f"Допустимые: {[e.value for e in ComplianceEventType]}",
            )

    events = bus.get_history(
        entity_id=entity_id,
        event_type=event_type_filter,
        severity=severity,
        limit=limit,
    )

    return [
        EventResponse(**e.to_dict())
        for e in events
    ]


@router.get("/api/events/stats", response_model=List[StatsResponse])
async def get_events_stats() -> List[StatsResponse]:
    """
    Статистика по compliance-событиям за последние 24h, 7d и 30d.

    Считается по событиям в памяти EventBus (не из DB).
    Возвращает список StatResponse для каждого периода.
    """
    bus = get_event_bus()
    results = []

    for period in ["24h", "7d", "30d"]:
        since = _resolve_period_since(period)
        stats = bus.get_stats(since=since)
        results.append(
            StatsResponse(
                period=period,
                total=stats["total"],
                by_type=stats["by_type"],
                by_severity=stats["by_severity"],
            )
        )

    return results


@router.post("/api/events/replay", response_model=ReplayResponse)
async def replay_events(body: ReplayRequest) -> ReplayResponse:
    """
    Replay событий из AuditEventRepository за указанный период.

    Читает события из БД (append-only audit trail) и возвращает их.
    Это НЕ повторное выполнение обработчиков — только чтение истории.

    Body:
      from_date — начало периода (ISO 8601)
      to_date   — конец периода (ISO 8601)

    Максимальный период: 90 дней.
    """
    # Валидация периода
    if body.from_date >= body.to_date:
        raise HTTPException(
            status_code=400,
            detail="from_date должен быть раньше to_date",
        )

    max_period = timedelta(days=90)
    if body.to_date - body.from_date > max_period:
        raise HTTPException(
            status_code=400,
            detail="Максимальный период для replay — 90 дней",
        )

    try:
        from database import AsyncSessionLocal
        from db_repository import AuditEventRepository

        async with AsyncSessionLocal() as session:
            repo = AuditEventRepository(session)
            db_events = await repo.replay_from(since=body.from_date)

        # Фильтруем до to_date (replay_from возвращает >= since)
        filtered = [
            e for e in db_events
            if e.created_at and e.created_at <= body.to_date
        ]

        events_out = [
            {
                "id":          e.id,
                "event_type":  e.event_type,
                "entity_type": e.entity_type,
                "entity_id":   e.entity_id,
                "actor":       e.actor,
                "payload":     e.payload or {},
                "created_at":  e.created_at.isoformat() if e.created_at else None,
            }
            for e in filtered
        ]

        log.info(
            "EventBus replay выполнен",
            extra={
                "from_date": body.from_date.isoformat(),
                "to_date":   body.to_date.isoformat(),
                "count":     len(events_out),
            },
        )

        return ReplayResponse(
            replayed=len(events_out),
            from_date=body.from_date.isoformat(),
            to_date=body.to_date.isoformat(),
            events=events_out,
        )

    except HTTPException:
        raise
    except Exception as exc:
        # БД недоступна (dev-режим) — возвращаем события из памяти EventBus
        log.warning(
            "EventBus replay: БД недоступна, возвращаем события из памяти",
            extra={"error": str(exc)},
        )
        bus = get_event_bus()

        # Конвертируем datetime в aware если нужно
        from_dt = body.from_date
        to_dt   = body.to_date
        if from_dt.tzinfo is None:
            from_dt = from_dt.replace(tzinfo=timezone.utc)
        if to_dt.tzinfo is None:
            to_dt = to_dt.replace(tzinfo=timezone.utc)

        memory_events = bus.get_history(limit=500)
        filtered_mem = [
            e for e in memory_events
            if from_dt <= e.timestamp <= to_dt
        ]

        events_out = [e.to_dict() for e in filtered_mem]

        return ReplayResponse(
            replayed=len(events_out),
            from_date=body.from_date.isoformat(),
            to_date=body.to_date.isoformat(),
            events=events_out,
        )


@router.get("/api/events/types")
async def list_event_types() -> Dict[str, Any]:
    """Возвращает все допустимые типы событий с их значениями."""
    return {
        "event_types": [
            {"name": e.name, "value": e.value}
            for e in ComplianceEventType
        ]
    }


@router.get("/api/events/{event_id}", response_model=Optional[EventResponse])
async def get_event(event_id: str) -> Optional[EventResponse]:
    """
    Возвращает событие по event_id из истории в памяти.

    Возвращает 404 если событие не найдено (не в памяти EventBus).
    Для исторических событий используйте /api/events/replay.
    """
    bus = get_event_bus()
    history = bus.get_history(limit=_MAX_HISTORY_SEARCH)

    for event in history:
        if event.event_id == event_id:
            return EventResponse(**event.to_dict())

    raise HTTPException(
        status_code=404,
        detail=f"Событие {event_id} не найдено в памяти. "
               "Используйте /api/events/replay для поиска в архиве.",
    )


@router.delete("/api/events/history", status_code=204)
async def clear_event_history() -> None:
    """
    Очищает историю событий в памяти EventBus.

    ВНИМАНИЕ: только для dev/testing. События в DB не затрагиваются.
    В production используйте только для отладки.
    """
    bus = get_event_bus()
    bus.clear_history()
    log.warning("EventBus: история событий очищена через API")
