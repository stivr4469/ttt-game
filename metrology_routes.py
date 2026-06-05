"""
FastAPI router for the Metrology Framework.

Replaces binary PASS/FAIL control measurements with continuous metrics
tracking (e.g., "% employees completed training: target 100%, current 87%").
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_auth, require_admin
from database import AsyncSessionLocal, engine
from log_config import get_logger
from metrology_models import MetricDefinition, MetricInstance

log = get_logger(__name__)

router = APIRouter(prefix="/api/metrology", tags=["metrology"])

# ── Table creation ─────────────────────────────────────────────────────────────

_tables_created = False


async def _ensure_tables() -> None:
    """Create metrology tables if they do not exist yet."""
    global _tables_created
    if _tables_created:
        return
    from metrology_models import MetricDefinition, MetricInstance  # noqa: F401
    from database import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    _tables_created = True
    log.info("Metrology tables ensured")


# ── Pydantic request/response models ──────────────────────────────────────────


class CreateDefinitionBody(BaseModel):
    name: str
    description: Optional[str] = None
    unit: str
    target_value: float
    target_direction: str  # "min", "max", "exact"
    category: Optional[str] = None
    control_id: Optional[str] = None


class UpdateDefinitionBody(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    unit: Optional[str] = None
    target_value: Optional[float] = None
    target_direction: Optional[str] = None
    category: Optional[str] = None
    control_id: Optional[str] = None
    is_active: Optional[bool] = None


class CreateInstanceBody(BaseModel):
    definition_id: str
    value: float
    source: Optional[str] = None  # "manual", "github", "okta", "auto"
    notes: Optional[str] = None


# ── Helpers ────────────────────────────────────────────────────────────────────


def _get_tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "00000000-0000-0000-0000-000000000001"


def _compute_status(definition: MetricDefinition, latest_value: Optional[float]) -> str:
    if latest_value is None:
        return "no_data"
    d = definition.target_direction
    if d == "max":
        return "on_target" if latest_value >= definition.target_value else "off_target"
    if d == "min":
        return "on_target" if latest_value <= definition.target_value else "off_target"
    # "exact"
    return "on_target" if abs(latest_value - definition.target_value) < 0.001 else "off_target"


def _compute_trend(values: list[float]) -> str:
    """Compare the last two readings to determine trend."""
    if len(values) < 2:
        return "no_data"
    diff = values[0] - values[1]  # values[0] is most recent
    if abs(diff) < 0.01:
        return "stable"
    return "improving" if diff > 0 else "declining"


def _def_to_dict(d: MetricDefinition) -> dict:
    return {
        "id": d.id,
        "tenant_id": d.tenant_id,
        "name": d.name,
        "description": d.description,
        "unit": d.unit,
        "target_value": d.target_value,
        "target_direction": d.target_direction,
        "category": d.category,
        "control_id": d.control_id,
        "is_active": d.is_active,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def _inst_to_dict(i: MetricInstance) -> dict:
    return {
        "id": i.id,
        "definition_id": i.definition_id,
        "tenant_id": i.tenant_id,
        "value": i.value,
        "recorded_at": i.recorded_at.isoformat() if i.recorded_at else None,
        "source": i.source,
        "notes": i.notes,
    }


# ── Seed data ──────────────────────────────────────────────────────────────────

_SEED_DEFINITIONS = [
    {
        "name": "Employee Training Completion",
        "description": "Percentage of employees who have completed all required security training courses.",
        "unit": "%",
        "target_value": 100.0,
        "target_direction": "max",
        "category": "training",
        "control_id": "CC1.4",
    },
    {
        "name": "Mean Time to Resolve Incidents",
        "description": "Average time (in hours) from incident detection to full resolution.",
        "unit": "hours",
        "target_value": 4.0,
        "target_direction": "min",
        "category": "incident_response",
        "control_id": "CC7.3",
    },
    {
        "name": "Access Review Completion",
        "description": "Percentage of access reviews completed on schedule.",
        "unit": "%",
        "target_value": 100.0,
        "target_direction": "max",
        "category": "access",
        "control_id": "CC6.3",
    },
    {
        "name": "MFA Adoption Rate",
        "description": "Percentage of users with multi-factor authentication enabled.",
        "unit": "%",
        "target_value": 100.0,
        "target_direction": "max",
        "category": "access",
        "control_id": "CC6.1",
    },
    {
        "name": "Vendor Risk Review Cycle",
        "description": "Average days between vendor risk assessments.",
        "unit": "days",
        "target_value": 90.0,
        "target_direction": "min",
        "category": "vendor",
        "control_id": "CC9.2",
    },
    {
        "name": "Policy Review Completion",
        "description": "Percentage of policies reviewed and approved within the required cycle.",
        "unit": "%",
        "target_value": 100.0,
        "target_direction": "max",
        "category": "compliance",
        "control_id": "CC2.1",
    },
    {
        "name": "Patch SLA Compliance",
        "description": "Percentage of critical patches applied within the defined SLA window.",
        "unit": "%",
        "target_value": 95.0,
        "target_direction": "max",
        "category": "operational",
        "control_id": "CC7.1",
    },
    {
        "name": "Backup Recovery Test Success Rate",
        "description": "Percentage of backup recovery tests that completed successfully.",
        "unit": "%",
        "target_value": 100.0,
        "target_direction": "max",
        "category": "operational",
        "control_id": "CC7.5",
    },
]

# Seed instances per definition: list of (days_ago, value, source) tuples
_SEED_INSTANCES: dict[str, list[tuple[int, float, str]]] = {
    "Employee Training Completion": [
        (1, 87.5, "auto"),
        (8, 82.0, "auto"),
        (15, 75.0, "auto"),
        (22, 68.0, "auto"),
    ],
    "Mean Time to Resolve Incidents": [
        (2, 3.2, "auto"),
        (9, 5.8, "auto"),
        (16, 4.1, "auto"),
        (23, 7.4, "auto"),
    ],
    "Access Review Completion": [
        (3, 100.0, "auto"),
        (10, 94.0, "auto"),
        (17, 88.0, "auto"),
    ],
    "MFA Adoption Rate": [
        (1, 96.3, "auto"),
        (8, 93.0, "auto"),
        (15, 89.5, "auto"),
    ],
    "Vendor Risk Review Cycle": [
        (5, 112.0, "manual"),
        (12, 98.0, "manual"),
        (19, 85.0, "manual"),
    ],
    "Policy Review Completion": [
        (4, 100.0, "manual"),
        (11, 100.0, "manual"),
        (18, 83.3, "manual"),
    ],
    "Patch SLA Compliance": [
        (2, 91.2, "auto"),
        (9, 78.5, "auto"),
        (16, 88.0, "auto"),
        (23, 95.0, "auto"),
    ],
    "Backup Recovery Test Success Rate": [
        (7, 100.0, "manual"),
        (14, 100.0, "manual"),
        (21, 83.3, "manual"),
    ],
}


async def _seed_defaults(session: AsyncSession, tenant_id: str) -> None:
    """Insert default metric definitions + sample instances for a new tenant."""
    now = datetime.now(timezone.utc)
    for defn in _SEED_DEFINITIONS:
        d = MetricDefinition(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            name=defn["name"],
            description=defn["description"],
            unit=defn["unit"],
            target_value=defn["target_value"],
            target_direction=defn["target_direction"],
            category=defn["category"],
            control_id=defn["control_id"],
            is_active=True,
            created_at=now,
        )
        session.add(d)
        await session.flush()  # get d.id

        for days_ago, value, source in _SEED_INSTANCES.get(defn["name"], []):
            inst = MetricInstance(
                id=str(uuid.uuid4()),
                definition_id=d.id,
                tenant_id=tenant_id,
                value=value,
                recorded_at=now - timedelta(days=days_ago),
                source=source,
                notes=None,
            )
            session.add(inst)

    await session.commit()
    log.info("Seeded default metric definitions for tenant %s", tenant_id)


# ── Endpoints ──────────────────────────────────────────────────────────────────


@router.get("/definitions")
async def list_definitions(user: dict = Depends(require_auth)) -> list[dict]:
    """List all active metric definitions for the current tenant."""
    await _ensure_tables()
    tenant_id = _get_tenant_id(user)
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(MetricDefinition)
            .where(
                MetricDefinition.tenant_id == tenant_id,
                MetricDefinition.is_active.is_(True),
            )
            .order_by(MetricDefinition.created_at)
        )
        definitions = result.scalars().all()
    return [_def_to_dict(d) for d in definitions]


@router.post("/definitions", status_code=201)
async def create_definition(
    body: CreateDefinitionBody,
    user: dict = Depends(require_auth),
) -> dict:
    """Create a new metric definition. Requires admin or auditor role."""
    if user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Admin or Auditor role required")
    await _ensure_tables()
    tenant_id = _get_tenant_id(user)
    now = datetime.now(timezone.utc)

    valid_directions = ("min", "max", "exact")
    if body.target_direction not in valid_directions:
        raise HTTPException(
            status_code=400,
            detail=f"target_direction must be one of {valid_directions}",
        )

    d = MetricDefinition(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        name=body.name,
        description=body.description,
        unit=body.unit,
        target_value=body.target_value,
        target_direction=body.target_direction,
        category=body.category,
        control_id=body.control_id,
        is_active=True,
        created_at=now,
    )
    async with AsyncSessionLocal() as session:
        session.add(d)
        await session.commit()

    log.info("Metric definition created: %s (%s)", d.name, d.id)
    return _def_to_dict(d)


@router.patch("/definitions/{definition_id}")
async def update_definition(
    definition_id: str,
    body: UpdateDefinitionBody,
    user: dict = Depends(require_auth),
) -> dict:
    """Update a metric definition. Requires admin or auditor role."""
    if user.get("role") not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Admin or Auditor role required")
    await _ensure_tables()
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(MetricDefinition).where(
                MetricDefinition.id == definition_id,
                MetricDefinition.tenant_id == tenant_id,
            )
        )
        d = result.scalar_one_or_none()
        if not d:
            raise HTTPException(status_code=404, detail="Metric definition not found")

        if body.name is not None:
            d.name = body.name
        if body.description is not None:
            d.description = body.description
        if body.unit is not None:
            d.unit = body.unit
        if body.target_value is not None:
            d.target_value = body.target_value
        if body.target_direction is not None:
            valid_directions = ("min", "max", "exact")
            if body.target_direction not in valid_directions:
                raise HTTPException(
                    status_code=400,
                    detail=f"target_direction must be one of {valid_directions}",
                )
            d.target_direction = body.target_direction
        if body.category is not None:
            d.category = body.category
        if body.control_id is not None:
            d.control_id = body.control_id
        if body.is_active is not None:
            d.is_active = body.is_active

        await session.commit()
        return _def_to_dict(d)


@router.delete("/definitions/{definition_id}", status_code=204)
async def delete_definition(
    definition_id: str,
    user: dict = Depends(require_admin),
) -> None:
    """Soft-delete a metric definition (set is_active=False). Admin only."""
    await _ensure_tables()
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(MetricDefinition).where(
                MetricDefinition.id == definition_id,
                MetricDefinition.tenant_id == tenant_id,
            )
        )
        d = result.scalar_one_or_none()
        if not d:
            raise HTTPException(status_code=404, detail="Metric definition not found")
        d.is_active = False
        await session.commit()

    log.info("Metric definition soft-deleted: %s", definition_id)


@router.get("/definitions/{definition_id}/history")
async def get_definition_history(
    definition_id: str,
    days: int = 90,
    user: dict = Depends(require_auth),
) -> list[dict]:
    """Return MetricInstance history for a definition, ordered by recorded_at desc."""
    await _ensure_tables()
    tenant_id = _get_tenant_id(user)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    async with AsyncSessionLocal() as session:
        # Verify the definition exists and belongs to this tenant
        defn_result = await session.execute(
            select(MetricDefinition).where(
                MetricDefinition.id == definition_id,
                MetricDefinition.tenant_id == tenant_id,
            )
        )
        d = defn_result.scalar_one_or_none()
        if not d:
            raise HTTPException(status_code=404, detail="Metric definition not found")

        result = await session.execute(
            select(MetricInstance)
            .where(
                MetricInstance.definition_id == definition_id,
                MetricInstance.tenant_id == tenant_id,
                MetricInstance.recorded_at >= cutoff,
            )
            .order_by(MetricInstance.recorded_at.desc())
        )
        instances = result.scalars().all()

    return [_inst_to_dict(i) for i in instances]


@router.post("/instances", status_code=201)
async def record_instance(
    body: CreateInstanceBody,
    user: dict = Depends(require_auth),
) -> dict:
    """Record a new metric measurement."""
    await _ensure_tables()
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as session:
        # Verify the definition exists and belongs to this tenant
        defn_result = await session.execute(
            select(MetricDefinition).where(
                MetricDefinition.id == body.definition_id,
                MetricDefinition.tenant_id == tenant_id,
                MetricDefinition.is_active.is_(True),
            )
        )
        d = defn_result.scalar_one_or_none()
        if not d:
            raise HTTPException(
                status_code=404, detail="Active metric definition not found"
            )

        inst = MetricInstance(
            id=str(uuid.uuid4()),
            definition_id=body.definition_id,
            tenant_id=tenant_id,
            value=body.value,
            recorded_at=datetime.now(timezone.utc),
            source=body.source or "manual",
            notes=body.notes,
        )
        session.add(inst)
        await session.commit()

    log.info(
        "Metric instance recorded: %s = %s %s",
        d.name,
        body.value,
        d.unit,
    )
    return _inst_to_dict(inst)


@router.get("/dashboard")
async def get_dashboard(user: dict = Depends(require_auth)) -> dict[str, Any]:
    """
    Returns a summary of all active metrics with latest values, status, and trend.

    Seeds 8 default metric definitions (plus sample instances) on first call
    if none exist for the tenant.
    """
    await _ensure_tables()
    tenant_id = _get_tenant_id(user)

    async with AsyncSessionLocal() as session:
        # Check if any definitions exist for this tenant
        count_result = await session.execute(
            select(MetricDefinition).where(
                MetricDefinition.tenant_id == tenant_id,
                MetricDefinition.is_active.is_(True),
            )
        )
        definitions = count_result.scalars().all()

        if not definitions:
            # Seed defaults for this tenant
            await _seed_defaults(session, tenant_id)
            # Re-fetch after seeding
            count_result2 = await session.execute(
                select(MetricDefinition).where(
                    MetricDefinition.tenant_id == tenant_id,
                    MetricDefinition.is_active.is_(True),
                )
            )
            definitions = count_result2.scalars().all()

        # Build dashboard metrics
        metrics = []
        for d in definitions:
            # Get last 2 instances for latest value + trend
            inst_result = await session.execute(
                select(MetricInstance)
                .where(
                    MetricInstance.definition_id == d.id,
                    MetricInstance.tenant_id == tenant_id,
                )
                .order_by(MetricInstance.recorded_at.desc())
                .limit(2)
            )
            recent = inst_result.scalars().all()

            latest_value: Optional[float] = recent[0].value if recent else None
            latest_at: Optional[str] = (
                recent[0].recorded_at.isoformat() if recent else None
            )
            values = [r.value for r in recent]
            trend = _compute_trend(values)
            status = _compute_status(d, latest_value)

            metrics.append(
                {
                    "id": d.id,
                    "name": d.name,
                    "description": d.description,
                    "unit": d.unit,
                    "target_value": d.target_value,
                    "target_direction": d.target_direction,
                    "category": d.category,
                    "control_id": d.control_id,
                    "latest_value": latest_value,
                    "latest_at": latest_at,
                    "status": status,
                    "trend": trend,
                }
            )

    total = len(metrics)
    on_target = sum(1 for m in metrics if m["status"] == "on_target")
    off_target = sum(1 for m in metrics if m["status"] == "off_target")
    pct_on_target = round(on_target / total * 100, 1) if total > 0 else 0.0

    return {
        "total_metrics": total,
        "on_target": on_target,
        "off_target": off_target,
        "pct_on_target": pct_on_target,
        "metrics": metrics,
    }
