#!/usr/bin/env python3
"""
DB-backed event consumer worker.

Решает проблему cross-process EventBus: агенты в subprocess/Celery не достигают
in-memory handlers. Этот воркер читает EventQueue из SQLite и вызывает handlers.

Запуск:
    python3 event_consumer.py              # бесконечный polling loop
    python3 event_consumer.py --once       # один проход (для тестов/Celery beat)
"""

import asyncio
import argparse
import json
import sys
from datetime import datetime, timezone

from log_config import get_logger
from database import AsyncSessionLocal
from db_repository import EventQueueRepository

log = get_logger(__name__)

POLL_INTERVAL = 5  # секунды между опросами


async def process_event(event_id: str, event_type: str, payload_str: str) -> None:
    """Обработать одно событие по его типу."""
    try:
        payload = json.loads(payload_str)
    except (json.JSONDecodeError, TypeError):
        payload = {}

    log.info("processing event", extra={"event_id": event_id, "event_type": event_type})

    # Dispatch по типу события
    if event_type == "evidence.added" or event_type == "evidence.created":
        await _handle_evidence_created(payload)
    elif event_type == "control.status_changed":
        await _handle_control_status_changed(payload)
    elif event_type == "risk.created":
        await _handle_risk_created(payload)
    elif event_type.startswith("vendor."):
        await _handle_vendor_event(event_type, payload)
    elif event_type.startswith("policy."):
        await _handle_policy_event(event_type, payload)
    else:
        log.debug("unhandled event type", extra={"event_type": event_type})


async def _handle_evidence_created(payload: dict) -> None:
    """Логируем факт создания/добавления evidence — можно расширить."""
    log.info(
        "evidence created via consumer",
        extra={"control_id": payload.get("control_id"), "source": payload.get("source")},
    )


async def _handle_control_status_changed(payload: dict) -> None:
    """Обновить ControlStatus в БД при получении события."""
    from db_repository import ControlRepository

    control_id = payload.get("control_id") or payload.get("entity_id")
    new_status = payload.get("status") or payload.get("new_status")
    if not control_id or not new_status:
        log.debug(
            "control_status_changed: missing control_id or status, skipping",
            extra={"payload_keys": list(payload.keys())},
        )
        return
    async with AsyncSessionLocal() as session:
        repo = ControlRepository(session)
        await repo.update_status(control_id=control_id, status=new_status, updated_by="consumer")
        await session.commit()
    log.info(
        "control status updated via consumer",
        extra={"control_id": control_id, "status": new_status},
    )


async def _handle_risk_created(payload: dict) -> None:
    log.info("risk created via consumer", extra={"risk_id": payload.get("id")})


async def _handle_vendor_event(event_type: str, payload: dict) -> None:
    log.info(
        "vendor event via consumer",
        extra={"event_type": event_type, "vendor": payload.get("name")},
    )


async def _handle_policy_event(event_type: str, payload: dict) -> None:
    log.info(
        "policy event via consumer",
        extra={"event_type": event_type, "control_id": payload.get("control_id")},
    )


async def run_once() -> int:
    """Один проход: обработать все pending события. Возвращает кол-во обработанных."""
    processed = 0
    async with AsyncSessionLocal() as session:
        repo = EventQueueRepository(session)
        events = await repo.get_pending(limit=50)
        for event in events:
            try:
                await process_event(event.id, event.event_type, event.payload)
                await repo.mark_done(event.id)
                await session.commit()
                processed += 1
            except Exception as exc:
                log.error(
                    "failed to process event",
                    extra={"event_id": event.id, "error": str(exc)},
                )
                await repo.mark_failed(event.id, str(exc))
                await session.commit()
    return processed


async def run_forever() -> None:
    """Бесконечный polling loop."""
    log.info("event consumer started", extra={"poll_interval": POLL_INTERVAL})
    while True:
        try:
            count = await run_once()
            if count:
                log.info("processed events", extra={"count": count})
        except Exception as exc:
            log.error("consumer loop error", extra={"error": str(exc)})
        await asyncio.sleep(POLL_INTERVAL)


def main() -> None:
    parser = argparse.ArgumentParser(description="DB-backed event consumer")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Один проход вместо бесконечного loop",
    )
    args = parser.parse_args()

    if args.once:
        count = asyncio.run(run_once())
        print(f"Processed {count} events")
        sys.exit(0)
    else:
        asyncio.run(run_forever())


if __name__ == "__main__":
    main()
