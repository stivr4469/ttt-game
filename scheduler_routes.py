"""
Agent schedule CRUD API.

Endpoints
---------
GET    /api/v1/schedules              — list all schedules for tenant
POST   /api/v1/schedules              — create / upsert schedule
PATCH  /api/v1/schedules/{id}         — update cadence or enabled flag
DELETE /api/v1/schedules/{id}         — delete schedule
POST   /api/v1/schedules/{id}/run-now — trigger immediate run
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from auth import require_auth, require_admin
from database import AsyncSessionLocal
from models import AgentSchedule

log = logging.getLogger(__name__)

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"

router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    agent_name: str = Field(..., max_length=50)
    cadence_minutes: int = Field(default=1440, ge=1)
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    cadence_minutes: Optional[int] = Field(default=None, ge=1)
    enabled: Optional[bool] = None


class ScheduleOut(BaseModel):
    id: str
    agent_name: str
    cadence_minutes: int
    enabled: bool
    last_run_at: Optional[datetime]
    last_run_status: Optional[str]
    tenant_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Helper ────────────────────────────────────────────────────────────────────

def _tenant(payload: dict) -> str:
    return payload.get("tenant_id", DEFAULT_TENANT_ID)


async def _get_or_404(session, schedule_id: str, tenant_id: str) -> AgentSchedule:
    row: Optional[AgentSchedule] = await session.get(AgentSchedule, schedule_id)
    if row is None or row.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return row


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ScheduleOut])
async def list_schedules(payload: dict = Depends(require_auth)):
    tenant_id = _tenant(payload)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AgentSchedule).where(AgentSchedule.tenant_id == tenant_id)
        )
        rows = result.scalars().all()
    return [ScheduleOut.model_validate(r) for r in rows]


@router.post("", response_model=ScheduleOut, status_code=201)
async def create_schedule(body: ScheduleCreate, payload: dict = Depends(require_admin)):
    tenant_id = _tenant(payload)
    async with AsyncSessionLocal() as session:
        # Upsert: check if schedule for this agent already exists
        result = await session.execute(
            select(AgentSchedule).where(
                AgentSchedule.tenant_id == tenant_id,
                AgentSchedule.agent_name == body.agent_name,
            )
        )
        existing: Optional[AgentSchedule] = result.scalar_one_or_none()

        if existing is not None:
            existing.cadence_minutes = body.cadence_minutes
            existing.enabled = body.enabled
            await session.commit()
            await session.refresh(existing)
            _trigger_reload()
            return ScheduleOut.model_validate(existing)

        row = AgentSchedule(
            id=str(uuid.uuid4()),
            agent_name=body.agent_name,
            cadence_minutes=body.cadence_minutes,
            enabled=body.enabled,
            tenant_id=tenant_id,
            created_at=datetime.now(timezone.utc),
        )
        session.add(row)
        await session.commit()
        await session.refresh(row)

    _trigger_reload()
    return ScheduleOut.model_validate(row)


@router.patch("/{schedule_id}", response_model=ScheduleOut)
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    payload: dict = Depends(require_admin),
):
    tenant_id = _tenant(payload)
    async with AsyncSessionLocal() as session:
        row = await _get_or_404(session, schedule_id, tenant_id)
        if body.cadence_minutes is not None:
            row.cadence_minutes = body.cadence_minutes
        if body.enabled is not None:
            row.enabled = body.enabled
        await session.commit()
        await session.refresh(row)

    _trigger_reload()
    return ScheduleOut.model_validate(row)


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: str,
    payload: dict = Depends(require_admin),
):
    tenant_id = _tenant(payload)
    async with AsyncSessionLocal() as session:
        row = await _get_or_404(session, schedule_id, tenant_id)
        await session.delete(row)
        await session.commit()

    _trigger_reload()


@router.post("/{schedule_id}/run-now", response_model=ScheduleOut)
async def run_now(
    schedule_id: str,
    payload: dict = Depends(require_auth),
):
    """Trigger an immediate out-of-band run for this schedule."""
    # require_auth is the minimum — scanner or admin can trigger
    role = payload.get("role", "")
    if role not in ("admin", "scanner"):
        raise HTTPException(status_code=403, detail="Admin or Scanner role required")

    tenant_id = _tenant(payload)
    async with AsyncSessionLocal() as session:
        row = await _get_or_404(session, schedule_id, tenant_id)
        agent_name = row.agent_name
        sched_id = row.id

    # Fire and forget — don't block the HTTP response
    import asyncio
    from scheduler import _run_agent_job
    asyncio.create_task(_run_agent_job(sched_id, agent_name))

    # Return the schedule row (last_run_at not yet updated — will be written when job finishes)
    async with AsyncSessionLocal() as session:
        row = await _get_or_404(session, schedule_id, tenant_id)
        return ScheduleOut.model_validate(row)


# ── Reload helper ─────────────────────────────────────────────────────────────

def _trigger_reload() -> None:
    """
    Schedule a background reload of APScheduler jobs after a CRUD change.
    The scheduler instance lives in ui_server; we reach it via a lazy import
    to avoid a circular dependency at module load time.
    """
    import asyncio
    try:
        import ui_server as _ui
        sched = getattr(_ui, "_agent_scheduler", None)
        if sched is not None:
            from scheduler import reload_schedules
            asyncio.create_task(reload_schedules(sched))
    except Exception as exc:
        log.warning("Could not trigger scheduler reload: %s", exc)
