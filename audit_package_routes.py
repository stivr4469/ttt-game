"""
Audit Package Export API — A6.

GET /api/v1/audit-package

Экспортирует пакет аудита за указанный период: evidence, test results,
статусы контролей и открытые findings.

Query параметры:
  from_date   — ISO8601 дата начала периода (например 2026-01-01)
  to_date     — ISO8601 дата конца периода (например 2026-06-01)
  control_ids — опциональный список control_id/code (фильтр)
  format      — "zip" (по умолчанию) или "json"

Авторизация: require_auditor (роли admin / auditor).
"""
from __future__ import annotations

import io
import json
import zipfile
import datetime as _dt
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_auditor
from database import get_db
from models import (
    Control,
    ControlStatus,
    Evidence,
    Finding,
    TestControlMapping,
    TestDefinition,
    TestResult,
)

router = APIRouter(prefix="/api/v1/audit-package", tags=["audit-package"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_date(date_str: str, param_name: str) -> _dt.datetime:
    """Parse ISO8601 date string into a timezone-aware datetime (start of day UTC)."""
    try:
        d = _dt.date.fromisoformat(date_str)
        return _dt.datetime(d.year, d.month, d.day, tzinfo=_dt.timezone.utc)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid date format for '{param_name}': {date_str!r}. Use ISO8601, e.g. 2026-01-01",
        )


def _serialize_evidence(ev: Evidence) -> dict:
    return {
        "id": ev.id,
        "title": ev.title,
        "source": ev.source,
        "content": ev.content,
        "confidence_score": ev.confidence_score,
        "created_at": ev.created_at.isoformat() if ev.created_at else None,
    }


def _serialize_finding(f: Finding) -> dict:
    return {
        "id": f.id,
        "test_id": f.test_id,
        "resource_id": f.resource_id,
        "status": f.status,
        "severity": f.severity,
        "title": f.title,
        "owner_email": f.owner_email,
        "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
        "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
        "sla_due_at": f.sla_due_at.isoformat() if f.sla_due_at else None,
    }


def _serialize_test_result(tr: TestResult, td: TestDefinition) -> dict:
    return {
        "test_key": td.key,
        "test_title": td.title,
        "severity": td.severity,
        "resource_id": tr.resource_id,
        "status": tr.status,
        "evaluated_at": tr.evaluated_at.isoformat() if tr.evaluated_at else None,
    }


# ── Data fetching ─────────────────────────────────────────────────────────────

async def _fetch_controls(
    session: AsyncSession,
    control_ids: Optional[list[str]],
) -> list[Control]:
    """Load controls, optionally filtered by id/code list."""
    stmt = select(Control)
    if control_ids:
        stmt = stmt.where(
            (Control.id.in_(control_ids)) | (Control.code.in_(control_ids))
        )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def _fetch_evidence_for_control(
    session: AsyncSession,
    control_id: str,
    from_dt: _dt.datetime,
    to_dt: _dt.datetime,
) -> list[Evidence]:
    stmt = (
        select(Evidence)
        .where(
            Evidence.control_id == control_id,
            Evidence.created_at >= from_dt,
            Evidence.created_at <= to_dt,
        )
        .order_by(Evidence.created_at.asc())
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def _fetch_last_test_result_for_control(
    session: AsyncSession,
    control_id: str,
    from_dt: _dt.datetime,
    to_dt: _dt.datetime,
) -> Optional[tuple[TestResult, TestDefinition]]:
    """Return the latest TestResult (and its TestDefinition) for a control within the period."""
    # Find test_ids mapped to this control
    mapping_stmt = select(TestControlMapping.test_id).where(
        TestControlMapping.control_id == control_id
    )
    mapping_result = await session.execute(mapping_stmt)
    test_ids = [row[0] for row in mapping_result.all()]

    if not test_ids:
        return None

    # Subquery: latest evaluated_at for each test_id within the period
    subq = (
        select(
            TestResult.test_id,
            TestResult.resource_id,
            func.max(TestResult.evaluated_at).label("latest_at"),
        )
        .where(
            TestResult.test_id.in_(test_ids),
            TestResult.evaluated_at >= from_dt,
            TestResult.evaluated_at <= to_dt,
        )
        .group_by(TestResult.test_id, TestResult.resource_id)
        .subquery()
    )

    stmt = (
        select(TestResult, TestDefinition)
        .join(
            subq,
            (TestResult.test_id == subq.c.test_id)
            & (TestResult.resource_id == subq.c.resource_id)
            & (TestResult.evaluated_at == subq.c.latest_at),
        )
        .join(TestDefinition, TestDefinition.id == TestResult.test_id)
        .order_by(TestResult.evaluated_at.desc())
        .limit(1)
    )

    result = await session.execute(stmt)
    row = result.first()
    return (row[0], row[1]) if row else None


async def _fetch_open_findings_for_control(
    session: AsyncSession,
    control_id: str,
) -> list[Finding]:
    """Return open Findings linked to this control via TestControlMapping."""
    mapping_stmt = select(TestControlMapping.test_id).where(
        TestControlMapping.control_id == control_id
    )
    mapping_result = await session.execute(mapping_stmt)
    test_ids = [row[0] for row in mapping_result.all()]

    if not test_ids:
        return []

    stmt = (
        select(Finding)
        .where(
            Finding.test_id.in_(test_ids),
            Finding.status == "OPEN",
        )
        .order_by(Finding.severity.asc(), Finding.first_seen_at.asc())
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def _fetch_control_status(
    session: AsyncSession,
    control_id: str,
) -> Optional[str]:
    stmt = select(ControlStatus.status).where(ControlStatus.control_id == control_id)
    result = await session.execute(stmt)
    row = result.first()
    return row[0] if row else "UNKNOWN"


# ── Package assembly ──────────────────────────────────────────────────────────

async def _build_package(
    session: AsyncSession,
    from_dt: _dt.datetime,
    to_dt: _dt.datetime,
    control_ids: Optional[list[str]],
) -> dict:
    """Assemble the full audit package as a dict."""
    controls = await _fetch_controls(session, control_ids)

    generated_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
    total_evidence = 0
    controls_data: list[dict] = []

    for ctrl in controls:
        evidence_list = await _fetch_evidence_for_control(session, ctrl.id, from_dt, to_dt)
        test_result_row = await _fetch_last_test_result_for_control(session, ctrl.id, from_dt, to_dt)
        open_findings = await _fetch_open_findings_for_control(session, ctrl.id)
        status = await _fetch_control_status(session, ctrl.id)

        serialized_evidence = [_serialize_evidence(ev) for ev in evidence_list]
        total_evidence += len(serialized_evidence)

        control_entry: dict = {
            "control_id": ctrl.id,
            "control_code": ctrl.code,
            "control_title": ctrl.title,
            "framework_id": ctrl.framework_id,
            "status": status,
            "evidence": serialized_evidence,
            "findings_open": [_serialize_finding(f) for f in open_findings],
            "last_test_result": (
                _serialize_test_result(test_result_row[0], test_result_row[1])
                if test_result_row
                else None
            ),
        }
        controls_data.append(control_entry)

    manifest = {
        "generated_at": generated_at,
        "from_date": from_dt.date().isoformat(),
        "to_date": to_dt.date().isoformat(),
        "total_controls": len(controls_data),
        "total_evidence_items": total_evidence,
    }

    return {
        "manifest": manifest,
        "controls": controls_data,
    }


def _build_zip(package: dict, from_date: str, to_date: str) -> bytes:
    """Serialize the audit package as a ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # manifest.json at root
        zf.writestr(
            "manifest.json",
            json.dumps(package["manifest"], indent=2, ensure_ascii=False),
        )
        # One file per control under controls/
        for ctrl in package["controls"]:
            code = ctrl["control_code"]
            # Sanitize code for use as filename (e.g. "CC6.1" → safe)
            safe_code = code.replace("/", "_").replace("\\", "_")
            filename = f"controls/{safe_code}.json"
            zf.writestr(
                filename,
                json.dumps(ctrl, indent=2, ensure_ascii=False),
            )
    return buf.getvalue()


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("")
async def export_audit_package(
    from_date: str = Query(..., description="Start of period, ISO8601 date (e.g. 2026-01-01)"),
    to_date: str = Query(..., description="End of period, ISO8601 date (e.g. 2026-06-01)"),
    control_ids: Optional[list[str]] = Query(default=None, description="Filter by control id/code (optional)"),
    format: str = Query(default="zip", description="Output format: 'zip' or 'json'"),
    _user: dict = Depends(require_auditor),
    session: AsyncSession = Depends(get_db),
):
    """
    Export audit package for the specified period.

    Returns a ZIP archive (default) or JSON with evidence, test results,
    control statuses and open findings for each control.

    Requires auditor or admin role.
    """
    from_dt = _parse_date(from_date, "from_date")
    # to_date is inclusive: extend to end of day
    to_dt_base = _parse_date(to_date, "to_date")
    to_dt = to_dt_base + _dt.timedelta(days=1) - _dt.timedelta(seconds=1)

    if from_dt > to_dt:
        raise HTTPException(
            status_code=400,
            detail="from_date must be before or equal to to_date",
        )

    fmt = format.lower()
    if fmt not in ("zip", "json"):
        raise HTTPException(
            status_code=400,
            detail="format must be 'zip' or 'json'",
        )

    package = await _build_package(session, from_dt, to_dt, control_ids or None)

    if fmt == "json":
        return package

    # ZIP response
    zip_bytes = _build_zip(package, from_date, to_date)
    filename = f"audit_package_{from_date}_{to_date}.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
