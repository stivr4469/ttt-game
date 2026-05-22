"""Celery tasks для каждого compliance агента."""

import json
import os

from celery_app import celery_app
from log_config import get_logger
from constants import CONTROLS_MAP_FILE

log = get_logger(__name__)


def _load_controls_map() -> dict:
    if os.path.exists(CONTROLS_MAP_FILE):
        with open(CONTROLS_MAP_FILE) as f:
            return json.load(f)
    return {}


@celery_app.task(bind=True, name="tasks.run_scanner")
def run_scanner_task(self):
    log.info("Celery: starting scanner task", extra={"task_id": self.request.id})
    from scanner import main as run_scanner
    run_scanner(_load_controls_map())
    return {"status": "completed", "agent": "scanner"}


@celery_app.task(bind=True, name="tasks.run_hr_agent")
def run_hr_agent_task(self):
    log.info("Celery: starting hr_agent task", extra={"task_id": self.request.id})
    from hr_agent import main as run_hr
    run_hr(_load_controls_map())
    return {"status": "completed", "agent": "hr_agent"}


@celery_app.task(bind=True, name="tasks.run_github_agent")
def run_github_agent_task(self):
    log.info("Celery: starting github_agent task", extra={"task_id": self.request.id})
    from github_agent import main as run_github
    run_github(_load_controls_map())
    return {"status": "completed", "agent": "github_agent"}


@celery_app.task(bind=True, name="tasks.run_policy_agent")
def run_policy_agent_task(self):
    log.info("Celery: starting policy_agent task", extra={"task_id": self.request.id})
    from policy_agent import main as run_policy
    run_policy(_load_controls_map())
    return {"status": "completed", "agent": "policy_agent"}


@celery_app.task(bind=True, name="tasks.run_full_pipeline")
def run_full_pipeline_task(self):
    log.info("Celery: starting full pipeline", extra={"task_id": self.request.id})
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
