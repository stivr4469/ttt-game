"""
cac_routes.py — FastAPI роутер для Compliance-as-Code.

Регистрация в ui_server.py:
    from cac_routes import router as cac_router
    app.include_router(cac_router)
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query

from auth import require_auth, require_admin, require_auditor
from compliance_as_code import ComplianceAsCodeEngine, CaCControl

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cac", tags=["compliance-as-code"])

# Синглтон движка — инициализируется один раз при старте модуля
_engine = ComplianceAsCodeEngine()
_engine.load_controls()


# ---------------------------------------------------------------------------
# Вспомогательные
# ---------------------------------------------------------------------------

def _control_to_dict(c: CaCControl) -> dict:
    return {
        "control_id": c.control_id,
        "name": c.name,
        "framework": c.framework,
        "severity": c.severity,
        "check": c.check,
        "remediation": {
            k: v for k, v in c.remediation.items()
            if k != "command"  # не раскрываем команду в листинге
        },
        "sla_hours": c.sla_hours,
        "tags": c.tags,
    }


def _get_control_or_404(control_id: str) -> CaCControl:
    control = _engine.get_control(control_id)
    if not control:
        raise HTTPException(status_code=404, detail=f"Контроль '{control_id}' не найден")
    return control


# ---------------------------------------------------------------------------
# Роуты
# ---------------------------------------------------------------------------

@router.get("/controls")
async def list_controls(
    framework: Optional[str] = Query(None, description="Фильтр по фреймворку (SOC2, ISO27001, ...)"),
    severity: Optional[str] = Query(None, description="Фильтр по severity (critical, high, medium, low)"),
    tag: Optional[str] = Query(None, description="Фильтр по тегу"),
    payload: dict = Depends(require_auth),
):
    """Список всех загруженных CaC-контролей с опциональной фильтрацией."""
    controls = _engine.all_controls()

    if framework:
        controls = [c for c in controls if c.framework.lower() == framework.lower()]
    if severity:
        controls = [c for c in controls if c.severity.lower() == severity.lower()]
    if tag:
        controls = [c for c in controls if tag.lower() in [t.lower() for t in c.tags]]

    return {
        "total": len(controls),
        "controls": [_control_to_dict(c) for c in controls],
    }


@router.get("/controls/{control_id}")
async def get_control(control_id: str, payload: dict = Depends(require_auth)):
    """Получить детали одного контроля по ID."""
    control = _get_control_or_404(control_id)
    return _control_to_dict(control)


@router.post("/run")
async def run_all_checks(payload: dict = Depends(require_auth)):
    """Запустить проверки всех загруженных контролей."""
    log.info("CaC run_all запущен пользователем %s", payload.get("sub"))
    results = _engine.run_all()
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed
    return {
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "pass_rate": round(passed / len(results) * 100, 1) if results else 0,
        "results": [r.to_dict() for r in results],
    }


@router.post("/run/{control_id}")
async def run_single_check(control_id: str, payload: dict = Depends(require_auth)):
    """Запустить проверку одного контроля."""
    control = _get_control_or_404(control_id)
    log.info("CaC run/%s запущен пользователем %s", control_id, payload.get("sub"))
    result = _engine.run_check(control)
    return result.to_dict()


@router.post("/remediate/{control_id}")
async def trigger_remediation(control_id: str, payload: dict = Depends(require_auditor)):
    """
    Запустить ремедиацию для контроля.

    - requires_approval=false → выполняется сразу
    - requires_approval=true  → попадает в очередь ожидания approve
    """
    control = _get_control_or_404(control_id)
    actor = payload.get("sub", "unknown")
    log.info("CaC remediate/%s запрошена пользователем %s", control_id, actor)
    result = _engine.trigger_remediation(control, approved_by=actor)
    return result


@router.post("/approve/{control_id}")
async def approve_remediation(control_id: str, payload: dict = Depends(require_admin)):
    """
    Подтвердить pending ремедиацию (только admin).
    После подтверждения команда выполняется немедленно.
    """
    actor = payload.get("sub", "unknown")
    log.info("CaC approve/%s подтверждена пользователем %s", control_id, actor)
    result = _engine.approve_remediation(control_id, approver=actor)
    if result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=result["detail"])
    return result


@router.get("/pending")
async def get_pending_approvals(payload: dict = Depends(require_auditor)):
    """Список ремедиаций, ожидающих подтверждения."""
    pending = _engine.get_pending_approvals()
    return {
        "total": len(pending),
        "pending": pending,
    }


@router.post("/upload")
async def upload_control(
    file: UploadFile = File(..., description="YAML-файл с декларацией контроля"),
    payload: dict = Depends(require_admin),
):
    """
    Загрузить новый YAML-контроль (только admin).
    Файл валидируется и сохраняется в cac_controls/.
    """
    if not file.filename or not file.filename.endswith(".yaml"):
        raise HTTPException(status_code=400, detail="Допускаются только .yaml файлы")

    content = await file.read()
    if len(content) > 64 * 1024:  # 64 KB лимит
        raise HTTPException(status_code=413, detail="Файл слишком большой (макс. 64 KB)")

    control, errors = _engine.add_control_from_yaml_bytes(content, file.filename)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Ошибки валидации YAML", "errors": errors},
        )

    log.info("CaC: загружен новый контроль %s пользователем %s", control.control_id, payload.get("sub"))
    return {
        "status": "uploaded",
        "control": _control_to_dict(control),
    }


@router.get("/validate")
async def validate_all_yamls(payload: dict = Depends(require_auth)):
    """Проверить синтаксис всех YAML-файлов в cac_controls/."""
    validation_results = _engine.validate_all_files()
    valid_count = sum(1 for errors in validation_results.values() if not errors)
    invalid_files = {f: e for f, e in validation_results.items() if e}
    return {
        "total_files": len(validation_results),
        "valid": valid_count,
        "invalid": len(invalid_files),
        "results": {
            fname: {"valid": not errors, "errors": errors}
            for fname, errors in validation_results.items()
        },
    }
