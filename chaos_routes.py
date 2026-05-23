"""
chaos_routes.py — FastAPI роутер для Chaos Compliance Runner.

Эндпоинты позволяют инжектировать compliance-нарушения, восстанавливать
стостояние и просматривать SLA-статистику.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import require_auth, require_auditor

log = logging.getLogger(__name__)

# ── Singleton runner (один экземпляр на процесс) ──────────────────────────────

from chaos_runner import ChaosRunner, SLAResult, ScenarioName

_runner = ChaosRunner()

# История прогонов — максимум 100 записей (deque с ограничением)
_results_history: deque[dict] = deque(maxlen=100)

# ── Pydantic-модели запросов ──────────────────────────────────────────────────


class InjectRequest(BaseModel):
    scenario: Literal["public_s3", "mfa_disabled", "stale_user", "branch_protection"]


# ── Router ────────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/chaos", tags=["chaos"])


@router.post("/inject")
async def inject_single(
    body: InjectRequest,
    user: dict = Depends(require_auditor),
) -> dict:
    """
    Запускает один chaos-сценарий.

    Возвращает SLAResult с временными метками и флагом обнаружения.
    """
    log.info("chaos inject: scenario=%s by %s", body.scenario, user.get("email"))
    try:
        result: SLAResult = _runner.run_scenario(body.scenario)
    except Exception as exc:
        log.error("chaos inject failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Chaos injection failed: {exc}")

    _results_history.append(result.to_dict())
    return result.to_dict()


@router.post("/inject-all")
async def inject_all(
    user: dict = Depends(require_auditor),
) -> list[dict]:
    """
    Запускает все 4 chaos-сценария последовательно.

    Возвращает список SLAResult.
    """
    log.info("chaos inject-all: by %s", user.get("email"))
    try:
        results: list[SLAResult] = _runner.run_all()
    except Exception as exc:
        log.error("chaos inject-all failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Chaos injection failed: {exc}")

    for r in results:
        _results_history.append(r.to_dict())

    return [r.to_dict() for r in results]


@router.post("/restore")
async def restore_all(
    user: dict = Depends(require_auditor),
) -> dict:
    """
    Откатывает все выполненные инъекции хаоса.

    Возвращает отчёт: сколько ресурсов восстановлено и какие не удалось откатить.
    """
    log.info("chaos restore: by %s", user.get("email"))
    try:
        report = _runner.restore_all()
    except Exception as exc:
        log.error("chaos restore failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Chaos restore failed: {exc}")

    return report


@router.get("/results")
async def get_results(
    user: dict = Depends(require_auth),
) -> list[dict]:
    """
    История всех прогонов chaos-сценариев (последние 100).
    Доступна любому авторизованному пользователю.
    """
    return list(_results_history)


@router.get("/summary")
async def get_summary(
    user: dict = Depends(require_auth),
) -> dict:
    """
    Агрегированная статистика по всем прогонам:
    - avg_detection_ms — среднее время обнаружения (только успешные детекции)
    - detection_rate_pct — процент обнаружений
    - worst_case_ms — максимальное время обнаружения
    - total_runs — общее число прогонов
    - detected_count — число обнаружений
    - by_scenario — разбивка по сценариям
    """
    history = list(_results_history)

    if not history:
        return {
            "total_runs": 0,
            "detected_count": 0,
            "detection_rate_pct": 0.0,
            "avg_detection_ms": 0,
            "worst_case_ms": 0,
            "by_scenario": {},
        }

    total_runs = len(history)
    detected = [r for r in history if r.get("detected")]
    detected_count = len(detected)
    detection_rate_pct = round(detected_count / total_runs * 100, 1)

    detection_times = [r["detection_ms"] for r in detected if r.get("detection_ms", 0) > 0]
    avg_detection_ms = int(sum(detection_times) / len(detection_times)) if detection_times else 0
    worst_case_ms = max(detection_times) if detection_times else 0

    # Разбивка по сценариям
    scenarios: dict[str, dict] = {}
    for r in history:
        sc = r.get("scenario", "unknown")
        if sc not in scenarios:
            scenarios[sc] = {"runs": 0, "detected": 0, "avg_detection_ms": 0, "worst_ms": 0}
        scenarios[sc]["runs"] += 1
        if r.get("detected"):
            scenarios[sc]["detected"] += 1
        ms = r.get("detection_ms", 0)
        if ms > scenarios[sc]["worst_ms"]:
            scenarios[sc]["worst_ms"] = ms

    for sc, stats in scenarios.items():
        sc_times = [
            r["detection_ms"]
            for r in history
            if r.get("scenario") == sc and r.get("detected") and r.get("detection_ms", 0) > 0
        ]
        stats["avg_detection_ms"] = int(sum(sc_times) / len(sc_times)) if sc_times else 0
        stats["detection_rate_pct"] = (
            round(stats["detected"] / stats["runs"] * 100, 1) if stats["runs"] else 0.0
        )

    return {
        "total_runs": total_runs,
        "detected_count": detected_count,
        "detection_rate_pct": detection_rate_pct,
        "avg_detection_ms": avg_detection_ms,
        "worst_case_ms": worst_case_ms,
        "by_scenario": scenarios,
    }
