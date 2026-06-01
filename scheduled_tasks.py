"""
Celery задача для запуска одного TestDefinition по расписанию.

Задача run_test_definition:
  1. Загружает TestDefinition из БД (sync через asyncio.run)
  2. Запускает asserter из ASSERTERS[td.assertion_type](td.params)
     (использует td.params как resource и {} как пустой params, если
     assertion_type является «автономным» тестом без внешнего ресурса)
  3. Отправляет результат через httpx.post → /api/v1/test-results/batch
     с JWT-токеном сервисного аккаунта (SCHEDULER_JWT_TOKEN env var)
  4. При ошибке → retry (max_retries=2, countdown=60s)
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx

from celery_app import celery_app

log = logging.getLogger(__name__)


# ── Async helper ───────────────────────────────────────────────────────────────

def _run_async(coro):
    """
    Запускает корутину в новом event loop с явным управлением жизненным циклом.
    Использовать вместо bare asyncio.run() чтобы lifecycle был предсказуемым.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── Константы ──────────────────────────────────────────────────────────────────

API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")
BATCH_ENDPOINT = f"{API_BASE_URL}/api/v1/test-results/batch"

# JWT-токен сервисного аккаунта для авторизации запросов к API
# Формат: JWT, созданный через create_access_token({"sub": "scheduler@system", "role": "scanner"})
SCHEDULER_JWT_TOKEN = os.getenv("SCHEDULER_JWT_TOKEN", "")

# ── Async helper: загрузить TestDefinition ────────────────────────────────────


async def _fetch_test_definition(test_key: str) -> Any | None:
    """Загрузить TestDefinition по ключу через async DB-сессию."""
    from database import AsyncSessionLocal
    from models import TestDefinition
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(TestDefinition).where(TestDefinition.key == test_key)
        )
        td = result.scalar_one_or_none()
        if td is None:
            return None
        # Возвращаем dict, чтобы не тащить ORM-объект вне сессии
        return {
            "id": td.id,
            "key": td.key,
            "title": td.title,
            "producer": td.producer,
            "assertion_type": td.assertion_type,
            "params": td.params or {},
            "severity": td.severity,
            "enabled": td.enabled,
            "tenant_id": td.tenant_id,
        }


# ── Отправить результат в API ──────────────────────────────────────────────────


def _post_result(test_key: str, status: str, details: dict, tenant_id: str | None = None) -> None:
    """
    POST /api/v1/test-results/batch с результатом прогона.
    Использует cookie access_token или Bearer-заголовок, в зависимости от токена.
    """
    payload = {
        "producer": "celery-scheduler",
        "trigger": "scheduled",
        "actor": "scheduler@system",
        "results": [
            {
                "test_key": test_key,
                "resource_id": "*",
                "status": status,
                "evidence_title": f"Scheduled run: {test_key}",
                "evidence_content": "{}",
                "source": "SCHEDULER",
                "details": details,
            }
        ],
    }

    cookies: dict[str, str] = {}
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if tenant_id:
        headers["X-Tenant-ID"] = str(tenant_id)

    if SCHEDULER_JWT_TOKEN:
        # API использует cookie access_token (см. auth.py → require_auth)
        cookies["access_token"] = SCHEDULER_JWT_TOKEN

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                BATCH_ENDPOINT,
                json=payload,
                cookies=cookies,
                headers=headers,
            )
            resp.raise_for_status()
            log.info(
                "Scheduler: result submitted for '%s': status=%s run_id=%s",
                test_key,
                status,
                resp.json().get("run_id"),
            )
    except httpx.HTTPStatusError as exc:
        log.error(
            "Scheduler: HTTP %s when submitting result for '%s': %s",
            exc.response.status_code,
            test_key,
            exc.response.text[:200],
        )
        raise
    except httpx.RequestError as exc:
        log.error(
            "Scheduler: connection error when submitting result for '%s': %s",
            test_key,
            exc,
        )
        raise


# ── Celery задача ──────────────────────────────────────────────────────────────


@celery_app.task(
    name="run_test_definition",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
)
def run_test_definition(self, test_key: str, tenant_id: str | None = None) -> dict:
    """
    Запустить один TestDefinition и сохранить результат через batch_submit.

    Параметры:
        test_key: уникальный ключ теста (TestDefinition.key)
        tenant_id: тенант, которому принадлежит тест (из TestDefinition или beat schedule)

    Возвращает dict с результатом выполнения.
    """
    if tenant_id:
        from tasks import _set_tenant
        _set_tenant(tenant_id)
    log.info("Scheduler: starting test '%s' (task_id=%s tenant=%s)", test_key, self.request.id, tenant_id)

    # 1. Загрузить TestDefinition из БД
    try:
        td = _run_async(_fetch_test_definition(test_key))
    except Exception as exc:
        log.error("Scheduler: failed to load TestDefinition '%s': %s", test_key, exc, exc_info=True)
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30, max_retries=3)

    if td is None:
        log.warning("Scheduler: TestDefinition '%s' not found — skipping", test_key)
        return {"test_key": test_key, "status": "SKIPPED", "reason": "not_found"}

    # Resolve tenant_id from TestDefinition if not passed from beat schedule
    effective_tenant_id = tenant_id or td.get("tenant_id")
    if effective_tenant_id and not tenant_id:
        from tasks import _set_tenant
        _set_tenant(effective_tenant_id)

    if not td["enabled"]:
        log.info("Scheduler: TestDefinition '%s' is disabled — skipping", test_key)
        return {"test_key": test_key, "status": "SKIPPED", "reason": "disabled"}

    # 2. Запустить asserter
    from asserters import ASSERTERS

    assertion_type = td["assertion_type"]
    params = td["params"]

    asserter = ASSERTERS.get(assertion_type)
    if asserter is None:
        log.error(
            "Scheduler: unknown assertion_type '%s' for test '%s'",
            assertion_type,
            test_key,
        )
        status = "ERROR"
        details: dict = {
            "error": f"Unknown assertion_type: {assertion_type}",
            "ran_at": datetime.now(timezone.utc).isoformat(),
        }
    else:
        try:
            # Для автономных asserters (always_pass, always_fail, field_*) передаём
            # params как resource и {} как params, что позволяет тестировать
            # статические проверки без внешнего ресурса.
            passed = bool(asserter(params, params))
            status = "PASS" if passed else "FAIL"
            details = {
                "assertion_type": assertion_type,
                "ran_at": datetime.now(timezone.utc).isoformat(),
                "passed": passed,
            }
            log.info(
                "Scheduler: test '%s' assertion_type='%s' → %s",
                test_key,
                assertion_type,
                status,
            )
        except Exception as exc:
            log.warning(
                "Scheduler: asserter '%s' raised for test '%s': %s",
                assertion_type,
                test_key,
                exc,
                exc_info=True,
            )
            status = "ERROR"
            details = {
                "assertion_type": assertion_type,
                "error": str(exc),
                "ran_at": datetime.now(timezone.utc).isoformat(),
            }

    # 3. Отправить результат в API
    try:
        _post_result(test_key, status, details, tenant_id=effective_tenant_id)
    except Exception as exc:
        log.error(
            "Scheduler: failed to submit result for '%s': %s — will retry",
            test_key,
            exc,
            exc_info=True,
        )
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30, max_retries=3)

    return {"test_key": test_key, "status": status, "details": details}
