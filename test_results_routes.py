"""
Test Engine API — движок тестов поверх существующих агентов.
POST /api/v1/test-results/batch  — агенты пушат результаты прогона
GET  /api/v1/tests               — каталог тестов
GET  /api/v1/tests/{key}/history — история теста (time-series)
GET  /api/v1/controls/{control_id}/tests — тесты, гейтящие контроль
GET  /api/v1/findings            — выведенные findings из FAIL-переходов
GET  /api/v1/posture             — сводка % PASS, открытые findings, drift
"""
import asyncio
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from asserters import ASSERTERS
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from auth import require_agent_or_auth, require_auth, require_auditor
from database import AsyncSessionLocal
from db_repository import (
    ControlRepository,
    TestDefinitionRepository,
    TestResultRepository,
    TestRunRepository,
)
from models import Control, ControlStatus, TestControlMapping, TestDefinition, TestResult, TestRun
from audit_log_repository import AuditLogRepository
from finding_repository import FindingRepository

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["test-engine"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class TestOutcomeIn(BaseModel):
    test_key: str
    resource_id: str = "*"
    status: str              # PASS | FAIL | ERROR | NA
    evidence_title: str = ""
    evidence_content: str = "{}"
    source: str = "SYSTEM"
    details: dict = Field(default_factory=dict)


class BatchRequest(BaseModel):
    run_id: Optional[str] = None
    producer: str
    trigger: str = "manual"
    actor: Optional[str] = None
    results: list[TestOutcomeIn]


class TestCreateRequest(BaseModel):
    key: str
    title: str
    description: Optional[str] = None
    producer: str
    assertion_type: str
    params: dict = Field(default_factory=dict)
    severity: str = "MEDIUM"
    default_remediation: Optional[str] = None
    frequency_minutes: int = 1440
    controls: list[str] = Field(default_factory=list)   # список SOC2-кодов контролей для маппинга


class TestUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    assertion_type: Optional[str] = None
    params: Optional[dict] = None
    severity: Optional[str] = None
    default_remediation: Optional[str] = None
    frequency_minutes: Optional[int] = None
    enabled: Optional[bool] = None


# ── Helper: derive_control_status ─────────────────────────────────────────────

def _derive_status(statuses: list[str]) -> str:
    if not statuses:
        return "NOT_STARTED"
    if any(s == "FAIL" for s in statuses):
        return "FAIL"
    if any(s in ("ERROR", "NA") for s in statuses):
        return "IN_PROGRESS"
    return "PASS"


async def _rollup_control(control_id: str, session) -> None:
    repo = TestResultRepository(session)
    latest = await repo.latest_for_control(control_id)
    statuses = [r.status for r in latest]
    new_status = _derive_status(statuses)
    ctrl_repo = ControlRepository(session)
    await ctrl_repo.update_status(control_id, new_status)


# ── POST /api/v1/test-results/batch ──────────────────────────────────────────

@router.post("/test-results/batch")
async def batch_submit(request: Request, body: BatchRequest, payload: dict = Depends(require_agent_or_auth)) -> dict:
    async with AsyncSessionLocal() as session:
        run_repo = TestRunRepository(session)
        tr_repo = TestResultRepository(session)

        # Validate or create TestRun
        if body.run_id:
            run_check = await session.get(TestRun, body.run_id)
            if run_check is None:
                raise HTTPException(status_code=400, detail=f"run_id '{body.run_id}' not found")
            run_id = body.run_id
        else:
            run = await run_repo.create(
                producer=body.producer,
                trigger=body.trigger,
                actor=body.actor,
            )
            run_id = run.id

        # Preload all referenced TestDefinitions in one query (avoids N+1)
        keys = list({item.test_key for item in body.results})
        td_rows = await session.execute(
            select(TestDefinition)
            .options(selectinload(TestDefinition.mappings))
            .where(TestDefinition.key.in_(keys))
        )
        td_map: dict[str, TestDefinition] = {td.key: td for td in td_rows.scalars().all()}

        inserted = 0
        skipped = 0
        affected_controls: set = set()
        finding_repo = FindingRepository(session)
        fail_events: list[dict] = []
        pass_events: list[dict] = []

        for item in body.results:
            td = td_map.get(item.test_key)
            if td is None:
                # Auto-register unknown test_key instead of skipping
                td = TestDefinition(
                    id=str(uuid.uuid4()),
                    key=item.test_key,
                    title=item.test_key,
                    description=f"Auto-registered by {body.producer}",
                    producer=body.producer,
                    severity="MEDIUM",
                    assertion_type="auto",
                    enabled=True,
                    frequency_minutes=1440,
                )
                session.add(td)
                await session.flush()  # obtain td.id before referencing it
                if "control_id" in item.details:
                    session.add(TestControlMapping(
                        id=str(uuid.uuid4()),
                        test_id=td.id,
                        control_id=item.details["control_id"],
                    ))
                    await session.flush()
                # Eagerly load mappings to avoid lazy-load in async context
                await session.refresh(td, attribute_names=["mappings"])
                td_map[item.test_key] = td
                log.info("Auto-registered test_key '%s' for producer '%s'", item.test_key, body.producer)

            try:
                result = await tr_repo.insert_if_not_exists(
                    test_id=td.id,
                    run_id=run_id,
                    resource_id=item.resource_id,
                    status=item.status,
                    evidence_id=None,
                    details=item.details,
                )
                inserted += 1
                # Update findings based on drift (PASS/FAIL transition)
                result_id = result.id if result else ""
                if item.status == "FAIL":
                    await finding_repo.open_or_update(td, item.resource_id, result_id)
                    fail_events.append({
                        "test_key": item.test_key,
                        "status": item.status,
                        "resource_id": item.resource_id,
                        "severity": td.severity,
                        "control_ids": [m.control_id for m in td.mappings],
                    })
                elif item.status == "ERROR":
                    fail_events.append({
                        "test_key": item.test_key,
                        "status": item.status,
                        "resource_id": item.resource_id,
                        "severity": td.severity,
                        "control_ids": [m.control_id for m in td.mappings],
                    })
                elif item.status == "PASS":
                    await finding_repo.resolve(td.id, item.resource_id)
                    pass_events.append({
                        "test_key": item.test_key,
                        "status": item.status,
                        "resource_id": item.resource_id,
                        "control_ids": [m.control_id for m in td.mappings],
                    })
            except Exception as e:
                log.warning("Could not insert result for %s: %s", item.test_key, e)
                skipped += 1
                continue

            for mapping in td.mappings:
                affected_controls.add(mapping.control_id)

        # Finish the run
        try:
            await run_repo.finish(run_id, status="done")
        except Exception as e:
            log.warning("Failed to finish run %s: %s", run_id, e)

        # Rollup statuses for affected controls
        for ctrl_id in affected_controls:
            try:
                await _rollup_control(ctrl_id, session)
            except Exception as e:
                log.warning("Rollup failed for control %s: %s", ctrl_id, e)

        # Cross-walk: evidence-reuse — link passing tests to equivalent controls,
        # then derive their status via rollup (not direct PASS write).
        # This way an equivalent control stays FAIL if it has its own failing tests.
        from control_mapping import get_engine as _get_mapping_engine
        _cm_engine = _get_mapping_engine()
        propagated: set[str] = set()

        for ctrl_id in affected_controls:
            cs_row = (await session.execute(
                select(ControlStatus).where(ControlStatus.control_id == ctrl_id)
            )).scalar_one_or_none()
            if cs_row is None or cs_row.status != "PASS":
                continue
            mapping = _cm_engine.get_mappings_for_control(ctrl_id)
            if mapping is None:
                continue
            # Tests linked to this control — they are the evidence we reuse
            tcm_rows = (await session.execute(
                select(TestControlMapping).where(TestControlMapping.control_id == ctrl_id)
            )).scalars().all()
            test_ids = [t.test_id for t in tcm_rows]
            if not test_ids:
                continue
            # Collect all equivalent control IDs across all mapped frameworks
            equiv_ids: list[str] = []
            for framework_ids in (
                mapping.iso27001, mapping.nist_800_53, mapping.cis_v8,
                mapping.gdpr, mapping.hipaa, mapping.pci_dss_v4,
            ):
                equiv_ids.extend(framework_ids)
            for equiv_id in equiv_ids:
                if equiv_id in affected_controls:
                    continue  # already rolled up directly
                try:
                    # Reuse evidence: link each test to the equivalent control (idempotent)
                    for test_id in test_ids:
                        already = (await session.execute(
                            select(TestControlMapping).where(
                                TestControlMapping.test_id == test_id,
                                TestControlMapping.control_id == equiv_id,
                            )
                        )).scalar_one_or_none()
                        if already is None:
                            session.add(TestControlMapping(
                                test_id=test_id, control_id=equiv_id
                            ))
                    await session.flush()
                    # Derive status from real test results — audit-defensible
                    await _rollup_control(equiv_id, session)
                    propagated.add(equiv_id)
                except Exception as e:
                    log.warning("Cross-walk evidence-reuse failed %s → %s: %s", ctrl_id, equiv_id, e)

        await session.commit()

    # Fire SSE + outgoing webhooks after commit (non-blocking)
    _tenant_id: str = payload.get("tenant_id", "")
    from outbound_webhook import notify as _ob_notify
    if fail_events:
        from sse_routes import broadcast as _sse_broadcast
        from outgoing_webhook_service import deliver as _wh_deliver
        for ev in fail_events:
            event_type = "test.failed" if ev["status"] == "FAIL" else "test.error"
            asyncio.create_task(_sse_broadcast("test.result", ev))
            asyncio.create_task(_wh_deliver(event_type, ev))
            for ctrl_id in ev.get("control_ids", []):
                asyncio.create_task(_ob_notify(
                    "control.status_changed",
                    {"control_id": ctrl_id, "status": "FAIL", "test_key": ev["test_key"]},
                    tenant_id=_tenant_id or None,
                ))
    if pass_events:
        for ev in pass_events:
            for ctrl_id in ev.get("control_ids", []):
                asyncio.create_task(_ob_notify(
                    "control.status_resolved",
                    {"control_id": ctrl_id, "status": "PASS", "test_key": ev["test_key"]},
                    tenant_id=_tenant_id or None,
                ))

    return {
        "run_id": run_id,
        "inserted": inserted,
        "skipped": skipped,
        "affected_controls": len(affected_controls),
        "propagated_crosswalk": len(propagated),
    }


# ── GET /api/v1/tests ─────────────────────────────────────────────────────────

@router.get("/tests")
async def list_tests(
    producer: Optional[str] = None,
    severity: Optional[str] = None,
    enabled: bool = True,
    payload: dict = Depends(require_auth),
) -> list[dict]:
    async with AsyncSessionLocal() as session:
        repo = TestDefinitionRepository(session)
        tests = await repo.list_all(producer=producer, enabled_only=enabled)
        if severity:
            tests = [t for t in tests if t.severity == severity.upper()]
        return [
            {
                "id": t.id,
                "key": t.key,
                "title": t.title,
                "description": t.description,
                "producer": t.producer,
                "assertion_type": t.assertion_type,
                "severity": t.severity,
                "frequency_minutes": t.frequency_minutes,
                "enabled": t.enabled,
            }
            for t in tests
        ]


# ── GET /api/v1/tests/{key}/history ──────────────────────────────────────────

@router.get("/tests/{key}/history")
async def test_history(key: str, days: int = 30, payload: dict = Depends(require_auth)) -> dict:
    async with AsyncSessionLocal() as session:
        td_repo = TestDefinitionRepository(session)
        td = await td_repo.get_by_key(key)
        if not td:
            raise HTTPException(status_code=404, detail=f"Test '{key}' not found")

        tr_repo = TestResultRepository(session)
        results = await tr_repo.latest_by_test(td.id, limit=days * 10)

        by_day: dict = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0, "na": 0})
        for r in results:
            day = r.evaluated_at.strftime("%Y-%m-%d") if r.evaluated_at else "unknown"
            s = (r.status or "error").lower()
            if s in by_day[day]:
                by_day[day][s] += 1

        return {
            "key": key,
            "history": [{"date": d, **counts} for d, counts in sorted(by_day.items())],
        }


# ── GET /api/v1/controls/{control_id}/tests ───────────────────────────────────

@router.get("/controls/{control_id}/tests")
async def control_tests(control_id: str, payload: dict = Depends(require_auth)) -> dict:
    async with AsyncSessionLocal() as session:
        ctrl_result = await session.execute(
            select(Control).where(
                (Control.id == control_id) | (Control.code == control_id)
            )
        )
        ctrl = ctrl_result.scalar_one_or_none()
        if not ctrl:
            raise HTTPException(status_code=404, detail="Control not found")

        # Get all tests for this control in one join
        map_stmt = (
            select(TestDefinition, TestControlMapping)
            .join(TestControlMapping, TestControlMapping.test_id == TestDefinition.id)
            .where(TestControlMapping.control_id == ctrl.id)
        )
        rows = (await session.execute(map_stmt)).all()
        if not rows:
            return {"control_id": ctrl.id, "control_code": ctrl.code, "tests": []}

        test_ids = [td.id for td, _ in rows]
        td_by_id = {td.id: td for td, _ in rows}

        # Get latest result per test in one query (avoids N+1)
        latest_subq = (
            select(
                TestResult.test_id,
                func.max(TestResult.evaluated_at).label("max_at"),
            )
            .where(TestResult.test_id.in_(test_ids))
            .group_by(TestResult.test_id)
            .subquery()
        )
        latest_stmt = (
            select(TestResult)
            .join(
                latest_subq,
                (TestResult.test_id == latest_subq.c.test_id)
                & (TestResult.evaluated_at == latest_subq.c.max_at),
            )
        )
        latest_results_rows = (await session.execute(latest_stmt)).scalars().all()
        latest_by_test: dict[str, TestResult] = {}
        for r in latest_results_rows:
            if r.test_id not in latest_by_test:
                latest_by_test[r.test_id] = r

        result = []
        for test_id in test_ids:
            td = td_by_id[test_id]
            latest = latest_by_test.get(test_id)
            result.append({
                "test_key": td.key,
                "title": td.title,
                "severity": td.severity,
                "producer": td.producer,
                "last_status": latest.status if latest else "NOT_STARTED",
                "last_evaluated": latest.evaluated_at.isoformat() if latest else None,
            })

        return {"control_id": ctrl.id, "control_code": ctrl.code, "tests": result}


# ── GET /api/v1/posture ───────────────────────────────────────────────────────

@router.get("/posture")
async def get_posture(payload: dict = Depends(require_auth)) -> dict:
    """Сводка: % контролей PASS, открытые findings."""
    async with AsyncSessionLocal() as session:
        ctrl_status_result = await session.execute(select(ControlStatus))
        ctrl_statuses = ctrl_status_result.scalars().all()
        total_controls = len(ctrl_statuses)
        pass_controls = sum(1 for c in ctrl_statuses if c.status == "PASS")
        fail_controls = sum(1 for c in ctrl_statuses if c.status == "FAIL")

        latest_subq = (
            select(
                TestResult.test_id,
                TestResult.resource_id,
                func.max(TestResult.evaluated_at).label("max_at"),
            )
            .group_by(TestResult.test_id, TestResult.resource_id)
            .subquery()
        )
        open_findings = (
            await session.execute(
                select(func.count())
                .select_from(TestResult)
                .join(
                    latest_subq,
                    (TestResult.test_id == latest_subq.c.test_id)
                    & (TestResult.resource_id == latest_subq.c.resource_id)
                    & (TestResult.evaluated_at == latest_subq.c.max_at),
                )
                .where(TestResult.status == "FAIL")
            )
        ).scalar() or 0

        total_tests = (
            await session.execute(
                select(func.count())
                .select_from(TestDefinition)
                .where(TestDefinition.enabled.is_(True))
            )
        ).scalar() or 0

    return {
        "controls": {
            "total": total_controls,
            "pass": pass_controls,
            "fail": fail_controls,
            "not_started": total_controls - pass_controls - fail_controls,
            "pass_pct": round(pass_controls / total_controls * 100, 1) if total_controls else 0.0,
        },
        "findings": {"open": open_findings},
        "tests": {"total_defined": total_tests},
    }


# ── POST /api/v1/tests — создать тест-определение ─────────────────────────────

@router.post("/tests", status_code=201)
async def create_test(body: TestCreateRequest, payload: dict = Depends(require_auditor)) -> dict:
    """Создать новое тест-определение. Требует роль auditor."""
    if body.assertion_type not in ASSERTERS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown assertion_type '{body.assertion_type}'. Available: {sorted(ASSERTERS)}"
        )
    if body.severity.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        raise HTTPException(status_code=400, detail="severity must be CRITICAL|HIGH|MEDIUM|LOW")

    async with AsyncSessionLocal() as session:
        repo = TestDefinitionRepository(session)
        existing = await repo.get_by_key(body.key)
        if existing:
            raise HTTPException(status_code=409, detail=f"Test '{body.key}' already exists")

        obj, _ = await repo.upsert(
            key=body.key,
            title=body.title,
            description=body.description,
            producer=body.producer,
            assertion_type=body.assertion_type,
            params=body.params,
            severity=body.severity.upper(),
            default_remediation=body.default_remediation,
            frequency_minutes=body.frequency_minutes,
            enabled=True,
        )

        # Создать маппинги на контроли
        if body.controls:
            ctrl_result = await session.execute(
                select(Control).where(Control.code.in_(body.controls))
            )
            controls = ctrl_result.scalars().all()
            for ctrl in controls:
                existing_map = await session.execute(
                    select(TestControlMapping).where(
                        TestControlMapping.test_id == obj.id,
                        TestControlMapping.control_id == ctrl.id,
                    )
                )
                if existing_map.scalar_one_or_none() is None:
                    session.add(TestControlMapping(
                        id=str(uuid.uuid4()),
                        test_id=obj.id,
                        control_id=ctrl.id,
                    ))

        found_codes = {ctrl.code for ctrl in controls} if body.controls else set()
        unknown_controls = [c for c in body.controls if c not in found_codes]

        audit_repo = AuditLogRepository(session)
        await audit_repo.log(
            user_email=payload.get("sub", "unknown"),
            user_role=payload.get("role", "unknown"),
            action="test.created",
            resource_type="test_definition",
            resource_id=obj.key,
            detail={"title": obj.title, "producer": obj.producer},
        )
        await session.commit()
        return {
            "id": obj.id,
            "key": obj.key,
            "created": True,
            "mapped_controls": list(found_codes),
            "unknown_controls": unknown_controls,
        }


# ── PUT /api/v1/tests/{key} — обновить тест-определение ──────────────────────

@router.put("/tests/{key}")
async def update_test(key: str, body: TestUpdateRequest, payload: dict = Depends(require_auditor)) -> dict:
    """Обновить поля тест-определения. Требует роль auditor."""
    async with AsyncSessionLocal() as session:
        repo = TestDefinitionRepository(session)
        td = await repo.get_by_key(key)
        if not td:
            raise HTTPException(status_code=404, detail=f"Test '{key}' not found")

        if body.assertion_type is not None:
            if body.assertion_type not in ASSERTERS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unknown assertion_type '{body.assertion_type}'"
                )
            td.assertion_type = body.assertion_type

        if body.title is not None:
            td.title = body.title
        if body.description is not None:
            td.description = body.description
        if body.params is not None:
            td.params = body.params
        if body.severity is not None:
            if body.severity.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                raise HTTPException(status_code=400, detail="severity must be CRITICAL|HIGH|MEDIUM|LOW")
            td.severity = body.severity.upper()
        if body.default_remediation is not None:
            td.default_remediation = body.default_remediation
        if body.frequency_minutes is not None:
            td.frequency_minutes = body.frequency_minutes
        if body.enabled is not None:
            td.enabled = body.enabled

        audit_repo = AuditLogRepository(session)
        await audit_repo.log(
            user_email=payload.get("sub", "unknown"),
            user_role=payload.get("role", "unknown"),
            action="test.updated",
            resource_type="test_definition",
            resource_id=td.key,
            detail={"title": td.title, "severity": td.severity, "enabled": td.enabled},
        )
        await session.commit()
        return {
            "key": td.key,
            "title": td.title,
            "severity": td.severity,
            "enabled": td.enabled,
            "updated": True,
        }


# ── DELETE /api/v1/tests/{key} — отключить тест-определение ──────────────────

@router.delete("/tests/{key}")
async def disable_test(
    key: str,
    hard: bool = False,
    payload: dict = Depends(require_auditor),
) -> dict:
    """
    Soft-delete (enabled=False) по умолчанию.
    hard=true — физическое удаление из БД вместе со всеми TestResult и TestControlMapping (CASCADE).
    Требует роль auditor.
    """
    async with AsyncSessionLocal() as session:
        repo = TestDefinitionRepository(session)
        td = await repo.get_by_key(key)
        if not td:
            raise HTTPException(status_code=404, detail=f"Test '{key}' not found")

        audit_repo = AuditLogRepository(session)
        if hard:
            await session.delete(td)
            await audit_repo.log(
                user_email=payload.get("sub", "unknown"),
                user_role=payload.get("role", "unknown"),
                action="test.deleted",
                resource_type="test_definition",
                resource_id=key,
                detail={"hard": True},
            )
            await session.commit()
            return {"key": key, "deleted": True, "hard": True}
        else:
            td.enabled = False
            await audit_repo.log(
                user_email=payload.get("sub", "unknown"),
                user_role=payload.get("role", "unknown"),
                action="test.deleted",
                resource_type="test_definition",
                resource_id=key,
                detail={"hard": False, "soft_disabled": True},
            )
            await session.commit()
            return {"key": key, "disabled": True, "hard": False}


# ── POST /api/v1/tests/{key}/run — ручной запуск теста ───────────────────────

@router.post("/tests/{key}/run", status_code=202)
async def run_test_now(key: str, payload: dict = Depends(require_auditor)) -> dict:
    """Запустить тест немедленно через Celery-задачу. Требует роль auditor."""
    async with AsyncSessionLocal() as session:
        repo = TestDefinitionRepository(session)
        td = await repo.get_by_key(key)
        if not td:
            raise HTTPException(status_code=404, detail=f"Test '{key}' not found")
        if not td.enabled:
            raise HTTPException(status_code=409, detail=f"Test '{key}' is disabled")

    try:
        from scheduled_tasks import run_test_definition
        task = run_test_definition.delay(key)
        log.info("Manual trigger: test '%s' enqueued as %s by %s", key, task.id, payload.get("sub", "unknown"))
        return {"task_id": task.id, "test_key": key, "status": "queued"}
    except Exception as exc:
        log.error("Failed to enqueue test '%s': %s", key, exc)
        raise HTTPException(status_code=503, detail=f"Could not enqueue task — is Celery running? ({exc})")
