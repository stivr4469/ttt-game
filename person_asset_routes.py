"""
person_asset_routes.py — Person-centric Asset Inventory API.

Provides a unified view of each employee together with their linked devices,
background check status, and derived risk score — the "asset graph" view.

Routes:
  GET /api/v1/assets/people  — list persons with linked assets
  GET /api/v1/assets/summary — aggregate counts
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_auth
from database import AsyncSessionLocal
from models import BackgroundCheck, HREmployee, MDMDevice

log = logging.getLogger(__name__)

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"

router = APIRouter(prefix="/api/v1/assets", tags=["person-assets"])


# ── DB session dependency ─────────────────────────────────────────────────────

async def _get_session():
    async with AsyncSessionLocal() as session:
        yield session


# ── Helpers ───────────────────────────────────────────────────────────────────

def _device_compliance(devices: list) -> str:
    """Return 'ok' / 'warning' / 'unknown' based on device list."""
    if not devices:
        return "unknown"
    if all(d.compliant for d in devices):
        return "ok"
    return "warning"


def _risk_score(emp: HREmployee, devices: list, bg_status: Optional[str]) -> str:
    """
    Derive a simple risk label.
      high   — terminated employee still has active (non-compliant) devices
      medium — any non-compliant device OR pending background check
      low    — otherwise
    """
    is_terminated = emp.status == "terminated"
    has_devices = bool(devices)
    any_non_compliant = any(not d.compliant for d in devices)

    if is_terminated and has_devices and any_non_compliant:
        return "high"
    if any_non_compliant or bg_status == "pending":
        return "medium"
    return "low"


def _serialize_device(d: MDMDevice) -> Dict[str, Any]:
    return {
        "hostname": d.hostname,
        "os": d.os,
        "device_type": d.device_type,
        "compliant": d.compliant,
        "filevault": d.filevault_enabled,
        "edr": d.edr_installed,
        "edr_name": d.edr_name,
        "os_up_to_date": d.os_up_to_date,
        "last_check_in": d.last_check_in,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/people")
async def list_people_with_assets(
    _: dict = Depends(require_auth),
    session: AsyncSession = Depends(_get_session),
) -> List[Dict[str, Any]]:
    """
    Return every HREmployee with their linked MDM devices and latest
    background check status.
    """
    # Load employees
    emp_result = await session.execute(
        select(HREmployee).where(HREmployee.tenant_id == DEFAULT_TENANT_ID)
    )
    employees: list[HREmployee] = list(emp_result.scalars().all())

    # Load all MDM devices for this tenant, indexed by owner email
    dev_result = await session.execute(
        select(MDMDevice).where(MDMDevice.tenant_id == DEFAULT_TENANT_ID)
    )
    all_devices: list[MDMDevice] = list(dev_result.scalars().all())

    devices_by_email: Dict[str, list[MDMDevice]] = {}
    for dev in all_devices:
        devices_by_email.setdefault(dev.owner, []).append(dev)

    # Load latest background check per employee_email
    bg_result = await session.execute(
        select(BackgroundCheck).where(BackgroundCheck.tenant_id == DEFAULT_TENANT_ID)
    )
    all_bgs: list[BackgroundCheck] = list(bg_result.scalars().all())

    # Keep only latest bg check per email (by created_at)
    latest_bg: Dict[str, BackgroundCheck] = {}
    for bg in all_bgs:
        existing = latest_bg.get(bg.employee_email)
        if existing is None or bg.created_at > existing.created_at:
            latest_bg[bg.employee_email] = bg

    # Build response
    result: List[Dict[str, Any]] = []
    for emp in employees:
        emp_devices = devices_by_email.get(emp.email, [])
        bg = latest_bg.get(emp.email)
        bg_status = bg.status if bg else None

        result.append({
            "email": emp.email,
            "name": emp.name,
            "role": emp.role,
            "department": emp.department,
            "status": emp.status,
            "employment_type": emp.employment_type,
            "training_completed": emp.training_completed,
            "training_date": emp.training_date,
            "hire_date": emp.hire_date,
            "devices": [_serialize_device(d) for d in emp_devices],
            "bg_check_status": bg_status,
            "device_compliance": _device_compliance(emp_devices),
            "risk_score": _risk_score(emp, emp_devices, bg_status),
        })

    return result


@router.get("/summary")
async def assets_summary(
    _: dict = Depends(require_auth),
    session: AsyncSession = Depends(_get_session),
) -> Dict[str, Any]:
    """
    Return aggregate counts:
      total_people, active, terminated, on_leave,
      compliant_devices, non_compliant_devices,
      pending_bg_checks, total_devices
    """
    emp_result = await session.execute(
        select(HREmployee).where(HREmployee.tenant_id == DEFAULT_TENANT_ID)
    )
    employees: list[HREmployee] = list(emp_result.scalars().all())

    dev_result = await session.execute(
        select(MDMDevice).where(MDMDevice.tenant_id == DEFAULT_TENANT_ID)
    )
    devices: list[MDMDevice] = list(dev_result.scalars().all())

    bg_result = await session.execute(
        select(BackgroundCheck).where(BackgroundCheck.tenant_id == DEFAULT_TENANT_ID)
    )
    bg_checks: list[BackgroundCheck] = list(bg_result.scalars().all())

    # Unique latest bg per email
    latest_bg: Dict[str, BackgroundCheck] = {}
    for bg in bg_checks:
        existing = latest_bg.get(bg.employee_email)
        if existing is None or bg.created_at > existing.created_at:
            latest_bg[bg.employee_email] = bg

    return {
        "total_people": len(employees),
        "active": sum(1 for e in employees if e.status == "active"),
        "terminated": sum(1 for e in employees if e.status == "terminated"),
        "on_leave": sum(1 for e in employees if e.status == "on_leave"),
        "total_devices": len(devices),
        "compliant_devices": sum(1 for d in devices if d.compliant),
        "non_compliant_devices": sum(1 for d in devices if not d.compliant),
        "pending_bg_checks": sum(1 for bg in latest_bg.values() if bg.status == "pending"),
        "training_complete": sum(1 for e in employees if e.training_completed),
        "training_incomplete": sum(1 for e in employees if not e.training_completed),
    }
