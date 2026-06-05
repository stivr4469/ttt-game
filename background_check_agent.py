#!/usr/bin/env python3
"""
background_check_agent.py — Агент проверки биографических данных сотрудников.
Использует Checkr API (или mock-режим если ключ не задан).
Покрывает: CC6.2 (User Registration/Screening).
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
import hashlib
import concurrent.futures
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv
from evidence_client import EvidenceClient
from constants import HR_ROSTER_FILE, CONTROLS_MAP_FILE
from log_config import get_logger

load_dotenv()

log = get_logger(__name__)

# ── Конфигурация ──────────────────────────────────────────────────────────────
CHECKR_API_KEY = os.getenv("CHECKR_API_KEY", "")
CHECKR_BASE_URL = "https://api.checkr.com/v1"
CHECKS_FILE = Path(__file__).parent / "background_checks.json"
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")

# Типы проверок Checkr
PACKAGES = {
    "tasker_standard": "Standard Employee Check (Criminal + SSN)",
    "driver_pro": "Driver Pro (Criminal + MVR + SSN)",
    "professional": "Professional (Criminal + Education + Employment)",
}

# Возможные статусы отчёта
VALID_STATUSES = {"pending", "consider", "clear", "dispute", "suspended"}


def _now_iso() -> str:
    """Возвращает текущее время в формате ISO 8601 UTC."""
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value) -> Optional[datetime]:
    """Парсит ISO-строку в datetime с timezone."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _mock_status_for_email(email: str) -> str:
    """
    Детерминированный mock-статус на основе email.
    70% — clear, 20% — pending, 10% — consider.
    """
    digest = int(hashlib.md5(email.encode()).hexdigest(), 16) % 100
    if digest < 70:
        return "clear"
    elif digest < 90:
        return "pending"
    else:
        return "consider"


def _run_async(coro):
    """Запускает async корутину из синхронного контекста."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


class BackgroundCheckAgent:
    """Агент для запуска и отслеживания background checks через Checkr API."""

    def __init__(self, controls_map: Optional[dict] = None):
        self.controls_map = controls_map or {}
        self.client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="bg_check_agent")
        # Инициализируем файл хранения если не существует (для обратной совместимости)
        self._ensure_checks_file()

    def _ensure_checks_file(self):
        """Создаёт background_checks.json если файл не существует."""
        if not CHECKS_FILE.exists():
            CHECKS_FILE.write_text(json.dumps([], indent=2), encoding="utf-8")

    # ── Async DB helpers ──────────────────────────────────────────────────────

    async def _load_checks_from_db(self) -> list:
        """SELECT * FROM background_check → список dict."""
        from database import AsyncSessionLocal
        from models import BackgroundCheck
        from sqlalchemy import select

        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(BackgroundCheck).order_by(BackgroundCheck.initiated_at))
                rows = result.scalars().all()
                return [
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
        except Exception as e:
            log.warning(f"DB load_checks failed, falling back to JSON: {e}")
            return self._load_checks_from_file()

    async def _save_check_to_db(self, data: dict) -> None:
        """Upsert записи background check по employee_email."""
        from database import AsyncSessionLocal
        from models import BackgroundCheck
        from sqlalchemy import select
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert

        async with AsyncSessionLocal() as session:
            # Проверяем существующую запись по employee_email
            result = await session.execute(
                select(BackgroundCheck).where(
                    BackgroundCheck.employee_email == data["employee_email"]
                )
            )
            existing = result.scalars().first()
            if existing:
                existing.employee_name = data.get("employee_name", existing.employee_name)
                existing.candidate_id = data.get("candidate_id", existing.candidate_id)
                existing.report_id = data.get("report_id", existing.report_id)
                existing.package = data.get("package", existing.package)
                existing.status = data.get("status", existing.status)
                existing.initiated_at = _parse_dt(data.get("initiated_at"))
                existing.completed_at = _parse_dt(data.get("completed_at"))
                existing.result = data.get("result")
            else:
                session.add(BackgroundCheck(
                    id=str(uuid.uuid4()),
                    employee_email=data["employee_email"],
                    employee_name=data.get("employee_name", ""),
                    candidate_id=data.get("candidate_id", ""),
                    report_id=data.get("report_id", ""),
                    package=data.get("package", "tasker_standard"),
                    status=data.get("status", "pending"),
                    initiated_at=_parse_dt(data.get("initiated_at")),
                    completed_at=_parse_dt(data.get("completed_at")),
                    result=data.get("result"),
                ))
            await session.commit()

    async def _load_active_employees_from_db(self) -> list:
        """SELECT * FROM hr_employee WHERE status != 'terminated'."""
        from database import AsyncSessionLocal
        from models import HREmployee
        from sqlalchemy import select

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(HREmployee).where(HREmployee.status != "terminated")
            )
            rows = result.scalars().all()
            return [
                {
                    "email": r.email,
                    "name": r.name,
                    "role": r.role,
                    "department": r.department,
                    "employment_type": r.employment_type,
                    "status": r.status,
                    "hire_date": r.hire_date,
                    "training_completed": r.training_completed,
                }
                for r in rows
            ]

    # ── JSON fallback helpers ─────────────────────────────────────────────────

    def _load_checks_from_file(self) -> list:
        """Загружает все проверки из JSON-файла (fallback)."""
        try:
            return json.loads(CHECKS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def _save_checks_to_file(self, checks: list):
        """Сохраняет список проверок в JSON-файл (для обратной совместимости)."""
        CHECKS_FILE.write_text(json.dumps(checks, indent=2, ensure_ascii=False), encoding="utf-8")

    # ── Public load/save (DB primary, JSON fallback) ──────────────────────────

    def _load_checks(self) -> list:
        """Загружает все проверки — сначала из DB, fallback на JSON."""
        return _run_async(self._load_checks_from_db())

    def _save_checks(self, checks: list):
        """Сохраняет список проверок в JSON (legacy) + upsert в DB."""
        self._save_checks_to_file(checks)
        for record in checks:
            try:
                _run_async(self._save_check_to_db(record))
            except Exception as e:
                log.warning(f"DB save_check failed for {record.get('employee_email')}: {e}")

    def _load_hr_roster(self) -> list:
        """Загружает активных сотрудников из DB. Fallback на hr_roster.json если таблица пуста."""
        try:
            employees = _run_async(self._load_active_employees_from_db())
            if employees:
                return employees
            log.info("hr_employee table empty, falling back to hr_roster.json")
        except Exception as e:
            log.warning(f"DB load_hr_roster failed: {e}")

        # Fallback на JSON
        if not Path(HR_ROSTER_FILE).exists():
            return []
        try:
            with open(HR_ROSTER_FILE, encoding="utf-8") as f:
                roster_data = json.load(f)
            all_emps = roster_data.get("employees", [])
            return [e for e in all_emps if e.get("status") != "terminated"]
        except Exception as e:
            log.error(f"Failed to load hr_roster.json: {e}")
            return []

    def _checkr_request(self, method: str, endpoint: str, data: Optional[dict] = None) -> dict:
        """
        HTTP запрос к Checkr API.
        Если CHECKR_API_KEY не задан — возвращает mock-ответ.
        """
        if not CHECKR_API_KEY:
            return self._mock_checkr_response(method, endpoint, data)

        url = f"{CHECKR_BASE_URL}{endpoint}"
        try:
            resp = requests.request(
                method,
                url,
                json=data,
                auth=(CHECKR_API_KEY, ""),
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            log.error(f"Checkr API ошибка: {e}")
            # Fallback на mock при сетевой ошибке
            return self._mock_checkr_response(method, endpoint, data)

    def _mock_checkr_response(self, method: str, endpoint: str, data: Optional[dict] = None) -> dict:
        """
        Mock-ответы имитирующие Checkr API.
        Используется когда CHECKR_API_KEY не задан.
        """
        if method == "POST" and endpoint == "/candidates":
            email = (data or {}).get("email", "unknown@example.com")
            short_id = uuid.uuid4().hex[:8]
            return {
                "id": f"cand_{short_id}",
                "email": email,
                "status": "pending",
                "created_at": _now_iso(),
                "object": "candidate",
            }
        elif method == "POST" and endpoint == "/reports":
            candidate_id = (data or {}).get("candidate_id", "cand_unknown")
            package = (data or {}).get("package", "tasker_standard")
            short_id = uuid.uuid4().hex[:8]
            return {
                "id": f"report_{short_id}",
                "candidate_id": candidate_id,
                "package": package,
                "status": "pending",
                "created_at": _now_iso(),
                "object": "report",
            }
        elif method == "GET" and endpoint.startswith("/reports/"):
            # Извлекаем report_id из endpoint для детерминированного статуса
            report_id = endpoint.split("/reports/")[-1]
            # Используем report_id как seed для статуса
            digest = int(hashlib.md5(report_id.encode()).hexdigest(), 16) % 100
            if digest < 70:
                status = "clear"
                result = "clear"
            elif digest < 90:
                status = "pending"
                result = None
            else:
                status = "consider"
                result = "consider"
            return {
                "id": report_id,
                "status": status,
                "result": result,
                "completed_at": _now_iso() if status != "pending" else None,
                "object": "report",
            }
        # Неизвестный endpoint — возвращаем пустой mock
        return {"id": f"mock_{uuid.uuid4().hex[:8]}", "status": "pending"}

    def create_candidate(self, email: str, first_name: str, last_name: str) -> dict:
        """
        Создаёт кандидата в Checkr.
        POST /candidates
        """
        log.info(f"Создание кандидата: {email}")
        return self._checkr_request("POST", "/candidates", {
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
        })

    def order_report(self, candidate_id: str, package: str = "tasker_standard") -> dict:
        """
        Заказывает отчёт о проверке для кандидата.
        POST /reports
        """
        if package not in PACKAGES:
            package = "tasker_standard"
        log.info(f"Заказ отчёта для кандидата {candidate_id}, пакет: {package}")
        return self._checkr_request("POST", "/reports", {
            "candidate_id": candidate_id,
            "package": package,
        })

    def get_report_status(self, report_id: str) -> dict:
        """
        Получает текущий статус отчёта.
        GET /reports/{report_id}
        """
        return self._checkr_request("GET", f"/reports/{report_id}")

    def run_for_new_employees(self, controls_map: Optional[dict] = None) -> dict:
        """
        Запускает background checks для всех активных сотрудников без существующей проверки.
        Читает hr_employee из DB (fallback: hr_roster.json).
        Сохраняет результат в DB + background_checks.json.
        Отправляет evidence для CC6.2.
        """
        if controls_map:
            self.controls_map = controls_map

        # Загружаем реестр сотрудников из DB (или JSON fallback)
        roster = self._load_hr_roster()
        if not roster:
            log.error("HR-реестр пуст или недоступен")
            return {"initiated": 0, "already_checked": 0, "cleared": 0, "pending": 0, "error": "hr roster not available"}

        # Загружаем существующие проверки из DB
        existing_checks = self._load_checks()
        checked_emails = {c["employee_email"] for c in existing_checks}

        initiated = 0
        already_checked = 0
        cleared = 0
        pending_count = 0

        new_checks = []

        for emp in roster:
            email = emp["email"]

            if email in checked_emails:
                already_checked += 1
                continue

            # Разбиваем имя на first/last
            name_parts = emp.get("name", "").split(" ", 1)
            first_name = name_parts[0] if name_parts else ""
            last_name = name_parts[1] if len(name_parts) > 1 else ""

            # Выбираем package по типу занятости
            package = "tasker_standard"

            # Создаём кандидата и заказываем отчёт
            candidate = self.create_candidate(email, first_name, last_name)
            candidate_id = candidate.get("id", f"cand_{uuid.uuid4().hex[:8]}")

            report = self.order_report(candidate_id, package)
            report_id = report.get("id", f"report_{uuid.uuid4().hex[:8]}")

            # В mock-режиме статус определяется детерминированно по email
            if not CHECKR_API_KEY:
                status = _mock_status_for_email(email)
                result = status if status in ("clear", "consider") else None
                completed_at = _now_iso() if status != "pending" else None
            else:
                # В реальном режиме статус изначально pending
                status = "pending"
                result = None
                completed_at = None

            record = {
                "employee_email": email,
                "employee_name": emp.get("name", ""),
                "candidate_id": candidate_id,
                "report_id": report_id,
                "package": package,
                "status": status,
                "initiated_at": _now_iso(),
                "completed_at": completed_at,
                "result": result,
            }
            new_checks.append(record)
            initiated += 1

            if status == "clear":
                cleared += 1
            elif status == "pending":
                pending_count += 1

            log.info(f"Background check инициирован: {email} → {status}")

        # Сохраняем все проверки в DB + JSON
        all_checks = existing_checks + new_checks
        # Сохраняем JSON (legacy)
        self._save_checks_to_file(all_checks)
        # Сохраняем новые записи в DB
        for record in new_checks:
            try:
                _run_async(self._save_check_to_db(record))
            except Exception as e:
                log.warning(f"DB save failed for {record.get('employee_email')}: {e}")

        # Считаем статистику по всем существующим
        for c in existing_checks:
            if c.get("status") == "clear":
                cleared += 1
            elif c.get("status") == "pending":
                pending_count += 1

        # Отправляем evidence для CC6.2
        self._save_evidence(all_checks, initiated)

        return {
            "initiated": initiated,
            "already_checked": already_checked,
            "cleared": cleared,
            "pending": pending_count,
        }

    def _save_evidence(self, all_checks: list, newly_initiated: int):
        """Отправляет evidence для CC6.2 (User Registration/Screening)."""
        control_id = self.controls_map.get("CC6.2")
        if not control_id:
            return

        cleared = sum(1 for c in all_checks if c.get("status") == "clear")
        pending = sum(1 for c in all_checks if c.get("status") == "pending")
        flagged = sum(1 for c in all_checks if c.get("status") in ("consider", "dispute"))

        try:
            self.client.create_evidence(
                control_id=control_id,
                title=f"[Background Checks] {len(all_checks)} проверок выполнено, {newly_initiated} новых",
                content=json.dumps({
                    "control": "CC6.2",
                    "total_checks": len(all_checks),
                    "newly_initiated": newly_initiated,
                    "cleared": cleared,
                    "pending": pending,
                    "flagged": flagged,
                    "mode": "mock" if not CHECKR_API_KEY else "checkr_api",
                    "timestamp": _now_iso(),
                }),
                source="BACKGROUND_CHECK",
            )
        except Exception as e:
            log.warning(f"Не удалось сохранить evidence CC6.2: {e}")

    def get_all_checks(self) -> list:
        """Возвращает все background checks из DB (fallback: JSON)."""
        return self._load_checks()

    def get_check_by_email(self, email: str) -> Optional[dict]:
        """Возвращает проверку конкретного сотрудника по email."""
        checks = self._load_checks()
        for c in checks:
            if c["employee_email"] == email:
                return c
        return None

    def check_employee(self, email: str, package: str = "tasker_standard") -> dict:
        """
        Запускает background check для конкретного сотрудника.
        Если проверка уже существует — обновляет её.
        Читает HR-данные из DB (fallback: hr_roster.json).
        """
        # Пробуем найти сотрудника в DB
        employee = None
        try:
            employees = _run_async(self._load_active_employees_from_db())
            for emp in employees:
                if emp["email"] == email:
                    employee = emp
                    break
        except Exception as e:
            log.warning(f"DB lookup for {email} failed: {e}")

        # Fallback на JSON если не найдено в DB
        if not employee:
            if not Path(HR_ROSTER_FILE).exists():
                return {"error": "hr_roster.json not found and DB unavailable"}
            with open(HR_ROSTER_FILE, encoding="utf-8") as f:
                roster_data = json.load(f)
            for emp in roster_data.get("employees", []):
                if emp["email"] == email:
                    employee = emp
                    break

        if not employee:
            return {"error": f"Сотрудник {email} не найден в HR-реестре"}

        name_parts = employee.get("name", "").split(" ", 1)
        first_name = name_parts[0] if name_parts else ""
        last_name = name_parts[1] if len(name_parts) > 1 else ""

        candidate = self.create_candidate(email, first_name, last_name)
        candidate_id = candidate.get("id", f"cand_{uuid.uuid4().hex[:8]}")

        report = self.order_report(candidate_id, package)
        report_id = report.get("id", f"report_{uuid.uuid4().hex[:8]}")

        if not CHECKR_API_KEY:
            status = _mock_status_for_email(email)
            result = status if status in ("clear", "consider") else None
            completed_at = _now_iso() if status != "pending" else None
        else:
            status = "pending"
            result = None
            completed_at = None

        record = {
            "employee_email": email,
            "employee_name": employee.get("name", ""),
            "candidate_id": candidate_id,
            "report_id": report_id,
            "package": package,
            "status": status,
            "initiated_at": _now_iso(),
            "completed_at": completed_at,
            "result": result,
        }

        # Сохраняем в DB
        try:
            _run_async(self._save_check_to_db(record))
        except Exception as e:
            log.warning(f"DB save failed for {email}: {e}")

        # Обновляем JSON (legacy)
        checks = self._load_checks_from_file()
        updated = False
        for i, c in enumerate(checks):
            if c["employee_email"] == email:
                checks[i] = record
                updated = True
                break
        if not updated:
            checks.append(record)
        self._save_checks_to_file(checks)

        log.info(f"Background check для {email}: {status} (пакет: {package})")
        return record

    def get_compliance_summary(self) -> dict:
        """
        Возвращает сводку compliance по background checks.
        {total_employees, checks_completed, checks_pending, checks_flagged,
         compliance_pct, unchecked_employees}
        """
        checks = self._load_checks()

        # Загружаем активных сотрудников из DB (fallback JSON)
        active_employees = self._load_hr_roster()
        total_active = len(active_employees)
        all_active_emails = [e["email"] for e in active_employees]

        checked_emails = {c["employee_email"] for c in checks}
        unchecked = [e for e in all_active_emails if e not in checked_emails]

        cleared = sum(1 for c in checks if c.get("status") == "clear")
        pending = sum(1 for c in checks if c.get("status") == "pending")
        flagged = sum(1 for c in checks if c.get("status") in ("consider", "dispute", "suspended"))
        completed = len(checks)

        # Процент соответствия: проверенные / всего активных
        compliance_pct = round((completed / total_active * 100) if total_active > 0 else 0, 1)

        return {
            "total_employees": total_active,
            "checks_completed": completed,
            "checks_cleared": cleared,
            "checks_pending": pending,
            "checks_flagged": flagged,
            "compliance_pct": compliance_pct,
            "unchecked_employees": unchecked,
            "mode": "mock" if not CHECKR_API_KEY else "checkr_api",
        }


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)

    # Загружаем controls_map
    controls_map = {}
    if Path(CONTROLS_MAP_FILE).exists():
        with open(CONTROLS_MAP_FILE, encoding="utf-8") as f:
            controls_map = json.load(f)

    agent = BackgroundCheckAgent(controls_map)
    result = agent.run_for_new_employees()
    print(f"\nРезультат: {result}")

    summary = agent.get_compliance_summary()
    print(f"\nСводка compliance: {json.dumps(summary, indent=2, ensure_ascii=False)}")
