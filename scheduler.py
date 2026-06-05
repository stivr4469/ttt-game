"""
Continuous monitoring scheduler.

Loads AgentSchedule rows from the DB at startup and registers one
APScheduler IntervalTrigger job per enabled schedule.  After each run
it persists last_run_at and last_run_status back to the DB.

Public API
----------
create_scheduler() -> AsyncIOScheduler
    Build and return the scheduler (does not start it).
reload_schedules(scheduler) -> None
    Re-read all schedules from DB and sync jobs in-place.
    Call this after any CRUD on AgentSchedule.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select

from database import AsyncSessionLocal
from models import AgentSchedule

log = logging.getLogger(__name__)

ROOT = Path(__file__).parent

# ── Agent definitions (mirrors the AGENTS dict in ui_server.py) ───────────────
# Duplicated here to avoid a circular import with ui_server.py.
AGENTS: dict[str, dict] = {
    "scanner": {"label": "AWS Scanner",      "cmd": ["python3", "scanner.py"]},
    "prowler": {"label": "Prowler Runner",   "cmd": ["python3", "prowler_runner.py"]},
    "hr":      {"label": "HR Agent",         "cmd": ["python3", "hr_agent.py"]},
    "survey":  {"label": "Survey Agent",     "cmd": ["python3", "survey_agent.py"]},
    "github":  {"label": "GitHub Agent",     "cmd": ["python3", "github_agent.py"]},
    "policy":  {"label": "Policy Generator", "cmd": ["python3", "policy_agent.py", "--governance", "--ollama"]},
}

_JOB_PREFIX = "agent_schedule_"


# ── Core runner ───────────────────────────────────────────────────────────────

async def _run_agent_job(schedule_id: str, agent_name: str) -> None:
    """Run one agent subprocess and persist the outcome to DB."""
    agent = AGENTS.get(agent_name)
    if not agent:
        log.warning("Scheduler: unknown agent '%s' (schedule_id=%s)", agent_name, schedule_id)
        return

    log.info("Scheduler: starting agent '%s' (schedule_id=%s)", agent_name, schedule_id)
    status = "error"
    try:
        agent_env = {
            **os.environ,
            "DATABASE_URL": os.environ.get(
                "DATABASE_URL",
                f"sqlite+aiosqlite:///{ROOT}/compliance.db",
            ),
        }
        proc = await asyncio.create_subprocess_exec(
            *agent["cmd"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(ROOT),
            env=agent_env,
        )
        # Drain stdout so the process does not block on a full pipe buffer.
        async for _ in proc.stdout:
            pass
        await proc.wait()
        status = "ok" if proc.returncode == 0 else "error"
        log.info(
            "Scheduler: agent '%s' finished with code %s (schedule_id=%s)",
            agent_name,
            proc.returncode,
            schedule_id,
        )
    except Exception as exc:
        log.error(
            "Scheduler: agent '%s' raised %s (schedule_id=%s)",
            agent_name,
            exc,
            schedule_id,
            exc_info=True,
        )

    # Persist result
    try:
        async with AsyncSessionLocal() as session:
            row: Optional[AgentSchedule] = await session.get(AgentSchedule, schedule_id)
            if row is not None:
                row.last_run_at = datetime.now(timezone.utc)
                row.last_run_status = status
                await session.commit()
    except Exception as exc:
        log.error(
            "Scheduler: failed to persist run status for schedule_id=%s: %s",
            schedule_id,
            exc,
        )


# ── Schedule sync helpers ─────────────────────────────────────────────────────

def _job_id(schedule_id: str) -> str:
    return f"{_JOB_PREFIX}{schedule_id}"


async def _load_schedules() -> list[AgentSchedule]:
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(AgentSchedule))
        return list(result.scalars().all())


def _sync_jobs(scheduler: AsyncIOScheduler, schedules: list[AgentSchedule]) -> None:
    """Add / update / remove APScheduler jobs to match the DB state."""
    desired_ids = set()

    for sched in schedules:
        job_id = _job_id(sched.id)
        desired_ids.add(job_id)

        if not sched.enabled:
            # Remove job if it exists
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)
            continue

        trigger = IntervalTrigger(minutes=sched.cadence_minutes)
        if scheduler.get_job(job_id):
            scheduler.reschedule_job(job_id, trigger=trigger)
        else:
            scheduler.add_job(
                _run_agent_job,
                trigger=trigger,
                id=job_id,
                args=[sched.id, sched.agent_name],
                replace_existing=True,
                misfire_grace_time=300,
            )

    # Remove orphaned jobs (schedule row was deleted from DB)
    for job in scheduler.get_jobs():
        if job.id.startswith(_JOB_PREFIX) and job.id not in desired_ids:
            scheduler.remove_job(job.id)


# ── Public API ────────────────────────────────────────────────────────────────

def create_scheduler() -> AsyncIOScheduler:
    """Create and configure the AsyncIOScheduler (does not start it)."""
    return AsyncIOScheduler(timezone="UTC")


async def reload_schedules(scheduler: AsyncIOScheduler) -> None:
    """
    Re-read AgentSchedule rows from DB and sync APScheduler jobs.
    Safe to call while the scheduler is running.
    """
    try:
        schedules = await _load_schedules()
        _sync_jobs(scheduler, schedules)
        log.info("Scheduler: reloaded %d schedule(s)", len(schedules))
    except Exception as exc:
        log.error("Scheduler: reload_schedules failed: %s", exc, exc_info=True)
