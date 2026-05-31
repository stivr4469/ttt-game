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
    return results

from datetime import datetime
from pathlib import Path

# Маппинг: контроль → какой агент его пересчитывает
CONTROL_AGENT_MAP = {
    "CC8.1": "github",   # Change Authorization
    "CC5.3": "github",   # Change Management
    "CC3.4": "scanner",  # Change Assessment
    "CC6.1": "scanner",  # Logical Access
    "CC6.2": "hr",       # User Registration
    "CC6.3": "scanner",  # Least Privilege
    "CC6.8": "github",   # Anti-Malware / Dependabot
    "CC7.3": "github",   # Security Events / Advisories
}

@celery_app.task(name="tasks.rescan_control")
def rescan_control(control_id: str, trigger: str):
    """Пересканировать конкретный контроль по webhook-триггеру."""
    agent = CONTROL_AGENT_MAP.get(control_id)
    controls_map = _load_controls_map()
    log.info(f"Webhook trigger: {trigger} -> rescanning {control_id} via {agent}")
    
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
        log.error(f"Rescan failed for {control_id}: {e}")

    # Записать в лог
    _append_webhook_log({
        "control_id": control_id, 
        "trigger": trigger, 
        "agent": agent, 
        "ts": datetime.utcnow().isoformat()
    })

def _append_webhook_log(entry: dict):
    """Добавить запись в webhook_events.json, хранить последние 100."""
    log_file = Path(__file__).parent / "webhook_events.json"
    events = []
    if log_file.exists():
        try:
            events = json.loads(log_file.read_text())
        except (json.JSONDecodeError, ValueError):
            events = []
    events.append(entry)
    events = events[-100:]  # ротация — последние 100
    log_file.write_text(json.dumps(events, indent=2, ensure_ascii=False))

