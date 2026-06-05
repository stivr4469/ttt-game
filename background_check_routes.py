#!/usr/bin/env python3
"""
background_check_routes.py — API эндпоинты для Background Checks.
Покрывает: CC6.2 (User Registration/Screening).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Cookie
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select

from auth import decode_token, ROLES
from background_check_agent import BackgroundCheckAgent
from constants import CONTROLS_MAP_FILE
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/background-checks", tags=["background-checks"])

# Единственный экземпляр агента для всего модуля
_agent: Optional[BackgroundCheckAgent] = None


def _get_agent() -> BackgroundCheckAgent:
    """Ленивая инициализация агента (загружает controls_map при первом вызове)."""
    global _agent
    if _agent is None:
        controls_map = {}
        if Path(CONTROLS_MAP_FILE).exists():
            with open(CONTROLS_MAP_FILE, encoding="utf-8") as f:
                controls_map = json.load(f)
        _agent = BackgroundCheckAgent(controls_map)
    return _agent


# ── Pydantic модели запросов ──────────────────────────────────────────────────

class CheckEmployeeRequest(BaseModel):
    email: str
    package: str = "tasker_standard"


# ── Auth dependencies ─────────────────────────────────────────────────────────

async def require_auth(access_token: Optional[str] = Cookie(None)) -> dict:
    """Требует валидный JWT токен."""
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(access_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalid or expired")
    return payload


async def require_admin_or_auditor(payload: dict = Depends(require_auth)) -> dict:
    """Разрешает доступ только для Admin и Auditor."""
    role = payload.get("role", "")
    if role not in ("admin", "auditor"):
        raise HTTPException(status_code=403, detail="Admin or Auditor role required")
    return payload


async def require_admin(payload: dict = Depends(require_auth)) -> dict:
    """Разрешает доступ только для Admin."""
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return payload


# ── Эндпоинты ────────────────────────────────────────────────────────────────

@router.get("")
async def get_all_checks(payload: dict = Depends(require_admin_or_auditor)):
    """
    Возвращает все background checks.
    Читает из DB напрямую; fallback через агент (JSON).
    Доступ: Admin, Auditor.
    """
    try:
        from database import AsyncSessionLocal
        from models import BackgroundCheck

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(BackgroundCheck).order_by(BackgroundCheck.initiated_at)
            )
            rows = result.scalars().all()

        if rows:
            checks = [
                {
                    "employee_email": r.employee_email,
                    "employee_name": r.employee_name,
                    "candidate_id": r.candidate_id,
                    "report_id": r.report_id,
                    "package": r.package,
                    "status": r.status,
                    "initiated_at": r.initiated_at.isoformat() if r.initiated_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    "result": r.result,
                }
                for r in rows
            ]
        else:
            # Fallback на агент (читает JSON)
            checks = _get_agent().get_all_checks()

        return {"checks": checks, "total": len(checks)}
    except Exception as e:
        log.error(f"Ошибка получения списка проверок: {e}")
        raise HTTPException(status_code=500, detail="Не удалось загрузить проверки")


@router.get("/summary")
async def get_summary(payload: dict = Depends(require_admin_or_auditor)):
    """
    Возвращает сводку compliance по background checks.
    Доступ: Admin, Auditor.
    """
    try:
        summary = _get_agent().get_compliance_summary()
        return summary
    except Exception as e:
        log.error(f"Ошибка получения сводки: {e}")
        raise HTTPException(status_code=500, detail="Не удалось получить сводку")


@router.post("/run")
async def run_checks_for_new_employees(payload: dict = Depends(require_admin)):
    """
    Инициирует background checks для всех активных сотрудников без существующей проверки.
    Доступ: Admin.
    """
    try:
        log.info(f"Запуск background checks инициирован пользователем: {payload.get('sub')}")
        result = _get_agent().run_for_new_employees()
        return {
            "status": "ok",
            "message": f"Проверки запущены: {result['initiated']} новых",
            **result,
        }
    except Exception as e:
        log.error(f"Ошибка запуска background checks: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка выполнения: {str(e)}")


@router.post("/employee")
async def check_specific_employee(
    body: CheckEmployeeRequest,
    payload: dict = Depends(require_admin),
):
    """
    Запускает background check для конкретного сотрудника.
    Body: {email, package}
    Доступ: Admin.
    """
    # Валидируем package
    from background_check_agent import PACKAGES
    if body.package not in PACKAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Неверный package. Допустимые: {list(PACKAGES.keys())}",
        )

    try:
        log.info(f"Проверка сотрудника {body.email} (package={body.package}), инициатор: {payload.get('sub')}")
        record = _get_agent().check_employee(body.email, body.package)

        if "error" in record:
            raise HTTPException(status_code=404, detail=record["error"])

        return {"status": "ok", "check": record}
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Ошибка проверки сотрудника {body.email}: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка выполнения: {str(e)}")


@router.get("/employee/{email:path}")
async def get_employee_check(
    email: str,
    payload: dict = Depends(require_admin_or_auditor),
):
    """
    Возвращает статус background check для конкретного сотрудника.
    Доступ: Admin, Auditor.
    """
    try:
        record = _get_agent().get_check_by_email(email)
        if not record:
            return {"status": "not_checked", "employee_email": email, "check": None}
        return {"status": "found", "check": record}
    except Exception as e:
        log.error(f"Ошибка получения проверки для {email}: {e}")
        raise HTTPException(status_code=500, detail="Не удалось получить статус проверки")
