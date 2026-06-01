"""
Celery Beat расписание на основе TestDefinition.frequency_minutes из БД.

Запуск:
    celery -A beat_schedule beat --loglevel=info

При старте beat читает все enabled TestDefinition из БД и строит
динамическое расписание: каждый тест запускается каждые frequency_minutes минут.

Минимальный интервал: 1 минута (60 секунд).
"""

from __future__ import annotations

import asyncio
import logging

from celery_app import celery_app  # noqa: F401 — импорт нужен для конфигурации

log = logging.getLogger(__name__)


# ── Async loader ───────────────────────────────────────────────────────────────


async def _load_enabled_tests() -> list[dict]:
    """
    Загрузить все enabled TestDefinition из БД.
    Возвращает список dict с полями key и frequency_minutes.
    """
    try:
        from database import AsyncSessionLocal
        from models import TestDefinition
        from sqlalchemy import select

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(TestDefinition.key, TestDefinition.frequency_minutes, TestDefinition.tenant_id)
                .where(TestDefinition.enabled.is_(True))
            )
            rows = result.all()
            return [
                {
                    "key": row.key,
                    "frequency_minutes": row.frequency_minutes,
                    "tenant_id": row.tenant_id,
                }
                for row in rows
            ]
    except Exception as exc:
        log.critical(
            "Beat schedule is EMPTY due to DB failure — no tests will run until restart. Error: %s",
            exc,
            exc_info=True,
        )
        return []


# ── Builder ────────────────────────────────────────────────────────────────────


def build_beat_schedule() -> dict:
    """
    Построить celery beat_schedule из TestDefinition.frequency_minutes.

    Каждый тест получает имя «test-{key}» и запускается с интервалом
    max(frequency_minutes, 1) * 60 секунд.
    """
    tests = asyncio.run(_load_enabled_tests())
    schedule: dict = {}
    for td in tests:
        freq_minutes = max(td.get("frequency_minutes") or 1440, 1)
        interval_seconds = freq_minutes * 60
        schedule[f"test-{td['key']}"] = {
            "task": "run_test_definition",
            "schedule": interval_seconds,
            "args": [td["key"]],
            "kwargs": {"tenant_id": td.get("tenant_id")},
        }
        log.debug(
            "beat_schedule: registered '%s' every %d min (%d s)",
            td["key"],
            freq_minutes,
            interval_seconds,
        )

    # Статические задачи — всегда присутствуют независимо от TestDefinition
    schedule["drain-evidence-retry-queue"] = {
        "task": "tasks.drain_evidence_retry_queue",
        "schedule": 60,  # каждую минуту
        "kwargs": {},
    }
    schedule["drain-event-queue"] = {
        "task": "tasks.drain_event_queue",
        "schedule": 10,  # каждые 10 секунд для low-latency cross-process events
        "kwargs": {},
    }
    schedule["sync-controls-map"] = {
        "task": "tasks.sync_controls_map_task",
        "schedule": 3600,  # каждый час
        "kwargs": {},
    }

    if not schedule:
        log.warning(
            "Beat schedule built with 0 tasks — verify DB has enabled TestDefinitions"
        )
    log.info("beat_schedule: loaded %d test(s) + static tasks into beat schedule", len(schedule) - 1)
    return schedule


# ── Применить расписание к Celery-конфигурации ─────────────────────────────────

celery_app.conf.beat_schedule = build_beat_schedule()
celery_app.conf.beat_schedule_filename = "/tmp/celerybeat-schedule"
