"""Celery tasks для каждого compliance агента."""

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from celery_app import celery_app
from log_config import get_logger
from constants import CONTROLS_MAP_FILE

log = get_logger(__name__)


def _load_controls_map() -> dict:
    if os.path.exists(CONTROLS_MAP_FILE):
        with open(CONTROLS_MAP_FILE) as f:
            return json.load(f)
    return {}


def _set_tenant(tenant_id: Optional[str]) -> None:
    """Propagate tenant_id into contextvar so any DB access inside the task is scoped."""
    if tenant_id:
        from tenant_context import set_current_tenant_id
        set_current_tenant_id(tenant_id)


@celery_app.task(bind=True, name="tasks.run_scanner")
def run_scanner_task(self, tenant_id: Optional[str] = None):
    _set_tenant(tenant_id)
    log.info("Celery: starting scanner task", extra={"task_id": self.request.id, "tenant_id": tenant_id})
    from scanner import main as run_scanner
    run_scanner(_load_controls_map())
    return {"status": "completed", "agent": "scanner"}


@celery_app.task(bind=True, name="tasks.run_hr_agent")
def run_hr_agent_task(self, tenant_id: Optional[str] = None):
    _set_tenant(tenant_id)
    log.info("Celery: starting hr_agent task", extra={"task_id": self.request.id, "tenant_id": tenant_id})
    from hr_agent import main as run_hr
    run_hr(_load_controls_map())
    return {"status": "completed", "agent": "hr_agent"}


@celery_app.task(bind=True, name="tasks.run_github_agent")
def run_github_agent_task(self, tenant_id: Optional[str] = None):
    _set_tenant(tenant_id)
    log.info("Celery: starting github_agent task", extra={"task_id": self.request.id, "tenant_id": tenant_id})
    from github_agent import main as run_github
    run_github(_load_controls_map())
    return {"status": "completed", "agent": "github_agent"}


@celery_app.task(bind=True, name="tasks.run_policy_agent")
def run_policy_agent_task(self, tenant_id: Optional[str] = None):
    _set_tenant(tenant_id)
    log.info("Celery: starting policy_agent task", extra={"task_id": self.request.id, "tenant_id": tenant_id})
    from policy_agent import main as run_policy
    run_policy(_load_controls_map())
    return {"status": "completed", "agent": "policy_agent"}


@celery_app.task(bind=True, name="tasks.run_full_pipeline")
def run_full_pipeline_task(self, tenant_id: Optional[str] = None):
    _set_tenant(tenant_id)
    log.info("Celery: starting full pipeline", extra={"task_id": self.request.id, "tenant_id": tenant_id})
    from scanner import main as run_scanner
    from hr_agent import main as run_hr
    from survey_agent import main as run_survey
    from github_agent import main as run_github

    controls_map = _load_controls_map()
    agents = [
        ("scanner", run_scanner),
        ("hr_agent", run_hr),
        ("survey_agent", run_survey),
        ("github_agent", run_github),
    ]
    results = []
    for name, fn in agents:
        try:
            fn(controls_map)
            results.append({"agent": name, "status": "ok"})
            log.info("Celery: agent done", extra={"agent": name})
        except Exception as e:
            log.error("Celery: agent failed", extra={"agent": name, "error": str(e)})
            results.append({"agent": name, "status": "error", "error": str(e)})
    return {"status": "completed", "results": results}


# Маппинг: контроль → какой агент его пересчитывает
CONTROL_AGENT_MAP = {
    "CC8.1": "github",
    "CC5.3": "github",
    "CC3.4": "scanner",
    "CC6.1": "scanner",
    "CC6.2": "hr",
    "CC6.3": "scanner",
    "CC6.8": "github",
    "CC7.3": "github",
}


async def _find_test_keys_for_control(control_id: str) -> list[str]:
    """Return TestDefinition.key values mapped to a SOC2 control code."""
    from database import AsyncSessionLocal
    from models import TestControlMapping, TestDefinition
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(TestDefinition.key)
            .join(TestControlMapping, TestControlMapping.test_id == TestDefinition.id)
            .where(TestControlMapping.control_id == control_id)
            .where(TestDefinition.enabled.is_(True))
        )
        return [row[0] for row in result.all()]


@celery_app.task(name="tasks.rescan_control")
def rescan_control(control_id: str, trigger: str, tenant_id: Optional[str] = None):
    """Пересканировать конкретный контроль по webhook-триггеру."""
    _set_tenant(tenant_id)
    agent = CONTROL_AGENT_MAP.get(control_id)
    controls_map = _load_controls_map()
    log.info("Webhook trigger: %s -> rescanning %s via %s", trigger, control_id, agent)

    try:
        if agent == "github":
            from github_agent import main as run_github
            run_github(controls_map)
        elif agent == "scanner":
            from scanner import main as run_scanner
            run_scanner(controls_map)
        elif agent == "hr":
            from hr_agent import main as run_hr
            run_hr(controls_map)
    except Exception as e:
        log.error("Rescan failed for %s: %s", control_id, e)

    # Also trigger TestDefinitions mapped to this control (new test-engine path)
    try:
        from scheduled_tasks import run_test_definition
        test_keys = asyncio.run(_find_test_keys_for_control(control_id))
        for key in test_keys:
            run_test_definition.delay(key, tenant_id=tenant_id)
            log.info("Webhook trigger: queued run_test_definition key=%s for control=%s", key, control_id)
    except Exception as exc:
        log.error("Failed to trigger TestDefinitions for control %s: %s", control_id, exc)

    _append_webhook_log({
        "control_id": control_id,
        "trigger": trigger,
        "agent": agent,
        "tenant_id": tenant_id,
        "ts": datetime.now(timezone.utc).isoformat(),
    })


@celery_app.task(bind=True, name="tasks.drain_event_queue")
def drain_event_queue(self, tenant_id: Optional[str] = None):
    """Обработать pending-события из EventQueue (cross-process consumer)."""
    _set_tenant(tenant_id)
    from event_consumer import run_once
    count = asyncio.run(run_once())
    log.info("Celery: drain_event_queue processed=%d", count)
    return {"status": "completed", "processed": count}


@celery_app.task(bind=True, name="tasks.drain_evidence_retry_queue")
def drain_evidence_retry_queue(self, tenant_id: Optional[str] = None):
    """Повторно доставить evidence из EventQueue в Evidence Tracker."""
    _set_tenant(tenant_id)

    async def _drain():
        from database import AsyncSessionLocal
        from models import EventQueue
        from sqlalchemy import select, update
        from datetime import datetime, timezone
        import requests as req

        evidence_url = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
        api_key = os.getenv("EVIDENCE_API_KEY", "")

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(EventQueue)
                .where(EventQueue.event_type == "evidence.retry")
                .where(EventQueue.status == "pending")
                .limit(50)
                .with_for_update(skip_locked=True)
            )
            rows = result.scalars().all()
            if not rows:
                return {"drained": 0}

            drained, failed = 0, 0
            for row in rows:
                row.status = "processing"
            await session.commit()

        for row in rows:
            try:
                data = json.loads(row.payload)
                headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
                if row.tenant_id:
                    headers["X-Tenant-ID"] = str(row.tenant_id)
                resp = req.post(
                    f"{evidence_url}/api/v1/evidence/",
                    json={
                        "control_id": data["control_id"],
                        "title":      data["title"],
                        "content":    data["content"],
                        "source":     data["source"],
                    },
                    headers=headers,
                    timeout=15,
                )
                resp.raise_for_status()
                new_status, error = "done", None
                drained += 1
            except Exception as exc:
                new_status, error = "failed", str(exc)[:500]
                failed += 1
                log.warning("drain_evidence_retry: failed for %s: %s", row.id, exc)

            async with AsyncSessionLocal() as session:
                await session.execute(
                    update(EventQueue)
                    .where(EventQueue.id == row.id)
                    .values(
                        status=new_status,
                        processed_at=datetime.now(timezone.utc),
                        error=error,
                    )
                )
                await session.commit()

        log.info("drain_evidence_retry: drained=%d failed=%d", drained, failed)
        return {"drained": drained, "failed": failed}

    return asyncio.run(_drain())


@celery_app.task(name="tasks.sync_controls_map_task")
def sync_controls_map_task():
    """Синхронизировать controls_map.json с Evidence Tracker API."""
    from sync_controls_map import sync_controls_map as _sync

    count = asyncio.run(_sync())
    log.info("sync_controls_map_task: synced %d controls", count)
    return {"status": "completed", "synced": count}


def _append_webhook_log(entry: dict) -> None:
    """Добавить запись в webhook_events.json, хранить последние 100."""
    log_file = Path(__file__).parent / "webhook_events.json"
    events: list = []
    if log_file.exists():
        try:
            events = json.loads(log_file.read_text())
        except (json.JSONDecodeError, ValueError):
            events = []
    events.append(entry)
    events = events[-100:]
    log_file.write_text(json.dumps(events, indent=2, ensure_ascii=False))
