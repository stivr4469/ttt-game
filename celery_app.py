"""Celery приложение для асинхронного запуска compliance агентов."""

import os
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "compliance_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=86400,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_routes={
        "tasks.run_scanner":      {"queue": "compliance"},
        "tasks.run_hr_agent":     {"queue": "compliance"},
        "tasks.run_github_agent": {"queue": "compliance"},
        "tasks.run_policy_agent": {"queue": "compliance"},
        "tasks.run_full_pipeline": {"queue": "compliance"},
    },
    task_default_queue="compliance",
)
