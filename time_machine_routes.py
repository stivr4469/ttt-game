"""
FastAPI роутер Time-Machine Audit.
Реконструирует compliance-состояние на произвольную историческую дату.

Паттерн аналогичен audit_timeline_routes.py.
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Header, Query
from sqlalchemy import func, select

from auth import decode_token, require_auth
from database import AsyncSessionLocal
from log_config import get_logger
from models import TestDefinition, TestResult
from time_machine import TimeMachineEngine, _parse_target_date

log = get_logger(__name__)

router = APIRouter(prefix="/api/time-machine", tags=["time-machine"])

# Единственный экземпляр движка на весь модуль (переиспользует HTTP-сессию)
_engine = TimeMachineEngine()


# ── Авторизация ─────────────────────────────────────────────────────────────────

def _require_auth(
    authorization: Optional[str] = Header(default=None),
    access_token: Optional[str] = Cookie(default=None),
) -> dict:
    """Требует любого авторизованного пользователя (Bearer header или cookie)."""
    user: Optional[dict] = None
    if access_token:
        user = decode_token(access_token)
    elif authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        user = decode_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Требуется авторизация")
    return user


def _require_auditor(user: dict = Depends(_require_auth)) -> dict:
    """Роли admin или auditor."""
    if user.get("role") not in ("admin", "Admin", "auditor", "Auditor"):
        raise HTTPException(
            status_code=403,
            detail="Доступ запрещён. Требуются роли: admin, auditor",
        )
    return user


# ── Вспомогательная функция ──────────────────────────────────────────────────────

def _validate_date(date_str: str, param_name: str = "date") -> str:
    """
    Валидирует строку даты ISO 8601.
    Выбрасывает HTTP 400 при невалидном формате.
    """
    try:
        _parse_target_date(date_str)
        return date_str
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Эндпоинты ────────────────────────────────────────────────────────────────────

@router.get("/snapshot")
async def get_snapshot(
    date: str = Query(..., description="Дата в ISO 8601, например 2026-01-14"),
    user: dict = Depends(_require_auth),
):
    """
    Реконструирует полное compliance-состояние на указанную дату.

    При отсутствии evidence — возвращает снапшот с пустыми контролями (не 404).
    Каждый снапшот содержит SHA-256 integrity_hash для audit trail.
    """
    _validate_date(date)
    try:
        snapshot = _engine.get_snapshot(date)
    except Exception as exc:
        log.error("Ошибка реконструкции снапшота", extra={"date": date, "error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Ошибка реконструкции: {exc}")

    log.info(
        "Снапшот запрошен",
        extra={"date": date, "by": user.get("email"), "controls": len(snapshot.controls)},
    )
    return snapshot.to_dict()


@router.get("/compare")
async def compare_snapshots(
    from_date: str = Query(..., alias="from", description="Начальная дата ISO 8601"),
    to_date: str = Query(..., alias="to", description="Конечная дата ISO 8601"),
    user: dict = Depends(_require_auth),
):
    """
    Сравнивает compliance-состояние между двумя датами.

    Возвращает: новые PASS, новые FAIL, улучшения, деградации, без изменений,
    дельту pass_rate.
    """
    _validate_date(from_date, "from")
    _validate_date(to_date, "to")

    try:
        diff = _engine.compare_snapshots(from_date, to_date)
    except Exception as exc:
        log.error(
            "Ошибка сравнения снапшотов",
            extra={"from": from_date, "to": to_date, "error": str(exc)},
        )
        raise HTTPException(status_code=500, detail=f"Ошибка сравнения: {exc}")

    log.info(
        "Сравнение снапшотов выполнено",
        extra={
            "from": from_date,
            "to": to_date,
            "by": user.get("email"),
            "changed": diff.get("total_changed"),
        },
    )
    return diff


@router.get("/timeline/{control_id}")
async def get_control_timeline(
    control_id: str,
    days: int = Query(default=90, ge=1, le=3650, description="Глубина истории в днях (1–3650)"),
    user: dict = Depends(_require_auth),
):
    """
    История изменений статуса конкретного контроля за последние N дней.

    Возвращает список событий: [{date, status, evidence_count}, ...]
    """
    try:
        timeline = _engine.get_timeline(control_id, days=days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        log.error(
            "Ошибка получения timeline контроля",
            extra={"control_id": control_id, "days": days, "error": str(exc)},
        )
        raise HTTPException(status_code=500, detail=f"Ошибка получения истории: {exc}")

    log.info(
        "Timeline контроля запрошен",
        extra={"control_id": control_id, "days": days, "by": user.get("email")},
    )
    return {
        "control_id": control_id,
        "days": days,
        "events": timeline,
        "total_events": len(timeline),
    }


@router.get("/drift")
async def get_drift_events(
    days: int = Query(default=30, ge=1, le=3650, description="Глубина анализа в днях (1–3650)"),
    user: dict = Depends(_require_auditor),
):
    """
    Возвращает события compliance-дрейфа за последние N дней.

    Дрейф = переход контроля между статусами (PASS→FAIL, FAIL→PASS, и т.д.).
    Сначала идут деградации (PASS→FAIL).

    Требует роль admin или auditor.
    """
    try:
        events = _engine.get_drift_events(days=days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        log.error(
            "Ошибка анализа дрейфа",
            extra={"days": days, "error": str(exc)},
        )
        raise HTTPException(status_code=500, detail=f"Ошибка анализа дрейфа: {exc}")

    log.info(
        "События дрейфа запрошены",
        extra={"days": days, "by": user.get("email"), "events": len(events)},
    )
    return {
        "days": days,
        "total_events": len(events),
        "degradations": sum(1 for e in events if e["drift_type"] == "degradation"),
        "improvements": sum(1 for e in events if e["drift_type"] == "improvement"),
        "events": events,
    }


@router.get("/available-dates")
async def get_available_dates(
    user: dict = Depends(_require_auth),
):
    """
    Возвращает список дат (YYYY-MM-DD), когда есть хотя бы одно evidence.

    Используется UI-календарём для подсветки доступных дат навигации.
    """
    try:
        dates = _engine.get_available_dates()
    except Exception as exc:
        log.error("Ошибка получения доступных дат", extra={"error": str(exc)})
        raise HTTPException(status_code=500, detail=f"Ошибка получения дат: {exc}")

    return {
        "total": len(dates),
        "dates": dates,
        "earliest": dates[0] if dates else None,
        "latest": dates[-1] if dates else None,
    }


# ── /api/v1/time-machine — compliance-позиция по TestResult ────────────────────
#
# Отдельный роутер с префиксом /api/v1/time-machine: для каждого теста
# возвращает последний TestResult ≤ указанного timestamp.
# Используется UI-страницей /time-machine.

compliance_router = APIRouter(prefix="/api/v1/time-machine", tags=["time-machine"])


@compliance_router.get("")
async def compliance_at(
    at: str = Query(..., description="ISO8601 datetime, e.g. 2025-12-01T00:00:00Z"),
    producer: Optional[str] = Query(None),
    payload: dict = Depends(require_auth),
) -> dict:
    """
    Возвращает compliance-позицию на указанный момент времени.
    Для каждого (test_id, resource_id) — последний результат ДО или В указанный timestamp.
    """
    try:
        as_of = datetime.fromisoformat(at.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid datetime format: {at!r}. Use ISO8601 e.g. 2025-12-01T00:00:00Z",
        )

    async with AsyncSessionLocal() as session:
        # Субзапрос: для каждой пары (test_id, resource_id) — max(evaluated_at) <= as_of
        subq = (
            select(
                TestResult.test_id,
                TestResult.resource_id,
                func.max(TestResult.evaluated_at).label("latest_at"),
            )
            .where(TestResult.evaluated_at <= as_of)
            .group_by(TestResult.test_id, TestResult.resource_id)
            .subquery()
        )

        stmt = (
            select(TestResult, TestDefinition)
            .join(
                subq,
                (TestResult.test_id == subq.c.test_id)
                & (TestResult.resource_id == subq.c.resource_id)
                & (TestResult.evaluated_at == subq.c.latest_at),
            )
            .join(TestDefinition, TestDefinition.id == TestResult.test_id)
        )

        if producer:
            stmt = stmt.where(TestDefinition.producer == producer)

        rows = (await session.execute(stmt)).all()

    results: list[dict] = []
    counts = {"PASS": 0, "FAIL": 0, "ERROR": 0, "NA": 0}

    for tr, td in rows:
        results.append(
            {
                "test_key": td.key,
                "title": td.title,
                "producer": td.producer,
                "severity": td.severity,
                "resource_id": tr.resource_id,
                "status": tr.status,
                "evaluated_at": tr.evaluated_at.isoformat() if tr.evaluated_at else None,
            }
        )
        counts[tr.status] = counts.get(tr.status, 0) + 1

    total = len(results)
    pass_rate = round(counts["PASS"] / total * 100, 1) if total > 0 else 0.0

    log.info(
        "Compliance-позиция запрошена",
        extra={
            "as_of": as_of.isoformat(),
            "producer": producer,
            "by": payload.get("sub"),
            "total": total,
            "pass_rate": pass_rate,
        },
    )

    return {
        "as_of": as_of.isoformat(),
        "total": total,
        "pass_rate": pass_rate,
        "counts": counts,
        "results": results,
    }
