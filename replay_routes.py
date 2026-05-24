"""
replay_routes.py — FastAPI роуты для Event Sourcing / Replay Engine.

Эндпоинты:
  GET  /api/replay/snapshot              — ReplaySnapshot на дату
  GET  /api/replay/control/{control_id}  — история одного контроля
  GET  /api/replay/timeline              — timeline точек для графика
  GET  /api/replay/diff                  — diff между двумя моментами
  GET  /api/replay/regression/{control_id} — найти регрессию PASS→FAIL
  GET  /api/replay/causation/{event_id}  — цепочка причинности
  GET  /api/replay/store/stats           — статистика EventStore

Все даты принимаются в ISO 8601 (UTC).
Ошибочные форматы дат → 400 Bad Request.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from event_sourcing import (
    ComplianceReplayEngine,
    EventStore,
    SnapshotDiff,
    SourcedEvent,
    get_event_store,
    get_replay_engine,
)
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/replay", tags=["replay"])


# ── Вспомогательные функции ────────────────────────────────────────────────────

def _parse_dt(value: str, param_name: str = "at") -> datetime:
    """
    Парсит ISO 8601 строку в timezone-aware datetime UTC.
    Поднимает HTTPException 400 при ошибке формата.
    """
    try:
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Неверный формат даты в параметре '{param_name}': {value!r}. "
                "Ожидается ISO 8601, например: 2026-01-15T10:00:00Z"
            ),
        )


def _validate_range(from_dt: datetime, to_dt: datetime) -> None:
    """Проверяет что from_dt < to_dt."""
    if from_dt >= to_dt:
        raise HTTPException(
            status_code=400,
            detail="from_dt должен быть строго раньше to_dt",
        )


# ── Pydantic-модели ─────────────────────────────────────────────────────────────

class SnapshotResponse(BaseModel):
    snapshot_at:      str
    overall_score:    float
    total_controls:   int
    pass_count:       int
    fail_count:       int
    unknown_count:    int
    control_statuses: Dict[str, str]
    evidence_counts:  Dict[str, int]
    risk_scores:      Dict[str, int]


class TransitionItem(BaseModel):
    occurred_at:  str
    from_status:  Optional[str]
    to_status:    Optional[str]
    event_id:     str
    event_type:   str
    actor:        str


class ControlHistoryResponse(BaseModel):
    control_id:  str
    from_dt:     str
    to_dt:       str
    transitions: List[Dict[str, Any]]


class TimelinePointResponse(BaseModel):
    point_at:   str
    score:      float
    pass_count: int
    fail_count: int
    total:      int


class DiffResponse(BaseModel):
    from_dt:        str
    to_dt:          str
    score_delta:    float
    changed:        List[Dict[str, Any]]
    new_risks:      List[str]
    resolved_risks: List[str]


class RegressionResponse(BaseModel):
    found:        bool
    control_id:   str
    occurred_at:  Optional[str]
    event_id:     Optional[str]
    actor:        Optional[str]
    payload:      Optional[Dict[str, Any]]


class CausationEventResponse(BaseModel):
    event_id:         str
    sequence_number:  int
    event_type:       str
    entity_type:      str
    entity_id:        str
    actor:            str
    payload:          Dict[str, Any]
    occurred_at:      str
    recorded_at:      str
    causation_id:     Optional[str]
    correlation_id:   Optional[str]


class StoreStatsResponse(BaseModel):
    total_events:     int
    min_sequence:     Optional[int]
    max_sequence:     Optional[int]
    entity_types:     Dict[str, int]
    event_types:      Dict[str, int]


# ── Роуты ──────────────────────────────────────────────────────────────────────

@router.get("/snapshot", response_model=SnapshotResponse)
async def get_snapshot(
    at: str = Query(..., description="Момент времени ISO 8601, например 2026-01-15T10:00:00Z"),
) -> SnapshotResponse:
    """
    Возвращает полное compliance-состояние на указанный момент времени.

    Вычисляется детерминистически через replay всех событий до `at`.
    Запрос идемпотентен: один и тот же `at` всегда даёт одинаковый результат.
    """
    target_dt = _parse_dt(at, "at")
    engine = get_replay_engine()

    try:
        snapshot = engine.replay_to(target_dt)
    except Exception as exc:
        log.error("replay_to failed", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Ошибка replay: {exc}")

    data = snapshot.to_dict()
    return SnapshotResponse(**data)


@router.get("/control/{control_id}", response_model=ControlHistoryResponse)
async def get_control_history(
    control_id: str,
    from_dt: Optional[str] = Query(None, description="Начало диапазона ISO 8601"),
    to_dt:   Optional[str] = Query(None, description="Конец диапазона ISO 8601"),
) -> ControlHistoryResponse:
    """
    Возвращает хронологическую историю изменений статуса контроля.

    Каждый элемент transitions содержит:
      occurred_at, from_status, to_status, event_id, event_type, actor.
    """
    now = datetime.now(timezone.utc)
    target_dt = _parse_dt(to_dt, "to_dt") if to_dt else now
    engine = get_replay_engine()

    try:
        history = engine.replay_control(control_id, target_dt)
    except Exception as exc:
        log.error("replay_control failed", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Ошибка replay контроля: {exc}")

    return ControlHistoryResponse(**history.to_dict())


@router.get("/timeline", response_model=List[TimelinePointResponse])
async def get_timeline(
    from_dt:    str = Query(..., description="Начало периода ISO 8601"),
    to_dt:      str = Query(..., description="Конец периода ISO 8601"),
    resolution: str = Query("day", description="Разрешение: hour | day | week"),
) -> List[TimelinePointResponse]:
    """
    Возвращает compliance timeline для построения графика.

    Каждая точка: момент времени, % PASS (score), pass_count, fail_count, total.
    resolution определяет шаг между точками.
    """
    from_datetime = _parse_dt(from_dt, "from_dt")
    to_datetime   = _parse_dt(to_dt,   "to_dt")
    _validate_range(from_datetime, to_datetime)

    if resolution not in ("hour", "day", "week"):
        raise HTTPException(
            status_code=400,
            detail=f"Неверное resolution: {resolution!r}. Допустимые: hour, day, week",
        )

    engine = get_replay_engine()

    try:
        points = engine.get_compliance_timeline(from_datetime, to_datetime, resolution)
    except Exception as exc:
        log.error("get_compliance_timeline failed", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Ошибка построения timeline: {exc}")

    return [TimelinePointResponse(**p.to_dict()) for p in points]


@router.get("/diff", response_model=DiffResponse)
async def get_diff(
    from_dt: str = Query(..., description="Первый момент ISO 8601"),
    to_dt:   str = Query(..., description="Второй момент ISO 8601"),
) -> DiffResponse:
    """
    Вычисляет разницу compliance-состояния между двумя моментами.

    Возвращает:
      score_delta   — изменение overall score
      changed       — контроли с изменившимся статусом
      new_risks     — появившиеся риски
      resolved_risks — исчезнувшие риски
    """
    from_datetime = _parse_dt(from_dt, "from_dt")
    to_datetime   = _parse_dt(to_dt,   "to_dt")
    _validate_range(from_datetime, to_datetime)

    engine = get_replay_engine()

    try:
        snap_a = engine.replay_to(from_datetime)
        snap_b = engine.replay_to(to_datetime)
        diff = engine.compute_diff(snap_a, snap_b)
    except Exception as exc:
        log.error("compute_diff failed", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Ошибка diff: {exc}")

    return DiffResponse(**diff.to_dict())


@router.get("/regression/{control_id}", response_model=RegressionResponse)
async def get_regression(
    control_id: str,
    from_dt: str = Query(..., description="Начало диапазона поиска ISO 8601"),
    to_dt:   str = Query(..., description="Конец диапазона поиска ISO 8601"),
) -> RegressionResponse:
    """
    Находит первый момент регрессии контроля (PASS → FAIL) в диапазоне.

    Возвращает:
      found=True  + детали события регрессии, если регрессия найдена.
      found=False + пустые поля, если регрессии не было.
    """
    from_datetime = _parse_dt(from_dt, "from_dt")
    to_datetime   = _parse_dt(to_dt,   "to_dt")
    _validate_range(from_datetime, to_datetime)

    engine = get_replay_engine()

    try:
        regression = engine.find_regression(control_id, from_datetime, to_datetime)
    except Exception as exc:
        log.error("find_regression failed", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Ошибка поиска регрессии: {exc}")

    if regression is None:
        return RegressionResponse(
            found=False,
            control_id=control_id,
            occurred_at=None,
            event_id=None,
            actor=None,
            payload=None,
        )

    r = regression.to_dict()
    return RegressionResponse(
        found=True,
        control_id=r["control_id"],
        occurred_at=r["occurred_at"],
        event_id=r["event_id"],
        actor=r["actor"],
        payload=r["payload"],
    )


@router.get("/causation/{event_id}", response_model=List[CausationEventResponse])
async def get_causation_chain(event_id: str) -> List[CausationEventResponse]:
    """
    Возвращает цепочку причинности для события.

    Рекурсивно обходит causation_id от данного события до первопричины.
    Цепочка упорядочена: первопричина первой, конечное событие последним.
    """
    store = get_event_store()

    try:
        chain = store.get_causation_chain(event_id)
    except Exception as exc:
        log.error("get_causation_chain failed", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Ошибка получения causation chain: {exc}")

    if not chain:
        raise HTTPException(
            status_code=404,
            detail=f"Событие {event_id!r} не найдено в EventStore",
        )

    return [CausationEventResponse(**e.to_dict()) for e in chain]


@router.get("/store/stats", response_model=StoreStatsResponse)
async def get_store_stats() -> StoreStatsResponse:
    """
    Статистика EventStore: количество событий, распределение по типам и entity.
    """
    store = get_event_store()
    all_events = store.get_all()

    entity_types: Dict[str, int] = {}
    event_types:  Dict[str, int] = {}

    for e in all_events:
        entity_types[e.entity_type] = entity_types.get(e.entity_type, 0) + 1
        event_types[e.event_type]   = event_types.get(e.event_type, 0) + 1

    min_seq = min((e.sequence_number for e in all_events), default=None)
    max_seq = max((e.sequence_number for e in all_events), default=None)

    return StoreStatsResponse(
        total_events=len(all_events),
        min_sequence=min_seq,
        max_sequence=max_seq,
        entity_types=entity_types,
        event_types=event_types,
    )
