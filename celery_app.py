"""Celery приложение для асинхронного запуска compliance агентов."""

import os
from celery import Celery

# Поддерживаем оба имени переменной: CELERY_BROKER_URL (новый) и REDIS_URL (legacy)
REDIS_URL = (
    os.getenv("CELERY_BROKER_URL")
    or os.getenv("REDIS_URL")
    or "redis://localhost:6379/0"
)
CELERY_BACKEND = (
    os.getenv("CELERY_RESULT_BACKEND")
    or os.getenv("REDIS_URL")
    or "redis://localhost:6379/0"
)

celery_app = Celery(
    "compliance_tasks",
    broker=REDIS_URL,
    backend=CELERY_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=86400,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    task_default_retry_delay=60,
    task_max_retries=3,
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "tasks.run_scanner":          {"queue": "compliance"},
        "tasks.run_hr_agent":         {"queue": "compliance"},
        "tasks.run_github_agent":     {"queue": "compliance"},
        "tasks.run_policy_agent":     {"queue": "compliance"},
        "tasks.run_full_pipeline":    {"queue": "compliance"},
        "run_test_definition":        {"queue": "compliance"},
    },
    task_default_queue="compliance",
)
