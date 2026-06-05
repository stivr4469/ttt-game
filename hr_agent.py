#!/usr/bin/env python3
"""
hr_agent.py — SOC 2 HR Compliance Scanner
Пять проверок человеческого фактора против Okta + hr_roster.json.
Покрывает: CC6.2 (offboarding/ghosts/dormant), CC9.2 (contractors), CC1.4 (training).
"""

import asyncio
import concurrent.futures
import os
import json
import logging
from datetime import datetime, date
from typing import Optional
from dotenv import load_dotenv
from base_compliance_agent import BaseComplianceAgent, AgentResult
from okta_client import OktaClient
from constants import HR_ROSTER_FILE, CONTROLS_MAP_FILE, TRAINING_GRACE_DAYS, DORMANT_DAYS

load_dotenv()


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


async def _load_roster_from_db() -> list:
    """SELECT всех сотрудников из hr_employee таблицы."""
    from database import AsyncSessionLocal
    from models import HREmployee
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(HREmployee))
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
                "training_date": r.training_date,
                "contract_end_date": r.contract_end_date,
                "termination_date": r.termination_date,
                "notes": r.notes,
            }
            for r in rows
        ]


def _load_roster() -> list:
    """Загружает реестр сотрудников из DB. Fallback на hr_roster.json если таблица пуста."""
    try:
        employees = _run_async(_load_roster_from_db())
        if employees:
            return employees
        logging.info("hr_employee table empty, falling back to hr_roster.json")
    except Exception as e:
        logging.warning(f"DB _load_roster failed: {e}")

    # Fallback на JSON
    if not os.path.exists(HR_ROSTER_FILE):
        return []
    try:
        with open(HR_ROSTER_FILE, encoding="utf-8") as f:
            roster_data = json.load(f)
        return roster_data.get("employees", [])
    except Exception as e:
        logging.error(f"Failed to load hr_roster.json: {e}")
        return []

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

OKTA_DOMAIN = os.getenv("OKTA_DOMAIN")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN")
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
COMPANY_NAME = os.getenv("COMPANY_NAME", "Marineso")



def parse_date(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def days_ago(d: Optional[date]) -> Optional[int]:
    if not d:
        return None
    return (date.today() - d).days


class HRAgent(BaseComplianceAgent):
    CONTROLS = {
        "CC6.2": "Authorized Users — Access Provisioning and Deprovisioning",
        "CC9.2": "Vendor Management — Contractor Access Control",
        "CC1.4": "Security Awareness Training Completion",
    }

    def authenticate(self) -> None:
        if not OKTA_DOMAIN or not OKTA_API_TOKEN:
            raise ValueError("OKTA_DOMAIN или OKTA_API_TOKEN не заданы в .env")
        self.roster = _load_roster()
        if not self.roster:
            raise ValueError("HR roster is empty")
        with OktaClient(OKTA_DOMAIN, OKTA_API_TOKEN) as okta:
            all_users_raw = okta._get_all("/users")
            active_users_raw = [u for u in all_users_raw if u.get("status") == "ACTIVE"]
        self.okta_all = {u["profile"]["login"]: u for u in all_users_raw}
        self.okta_active = {u["profile"]["login"]: u for u in active_users_raw}
        print(f"[Okta] Всего: {len(self.okta_all)} | ACTIVE: {len(self.okta_active)}\n")

    def run_checks(self) -> None:
        self.check_offboarding_gaps(self.okta_active, self.roster)
        print()
        self.check_ghost_accounts(self.okta_active, self.roster)
        print()
        self.check_contractor_expiry(self.okta_all, self.roster)
        print()
        self.check_training_overdue(self.roster)
        print()
        self.check_dormant_accounts(self.okta_active, self.roster)
        print()

    def check_offboarding_gaps(self, okta_active: dict, roster: list):
        """CC6.2: уволенные сотрудники с активным Okta-аккаунтом."""
        print("── Проверка 1: Offboarding gaps (CC6.2) ──")
        terminated = [e for e in roster if e.get("status") == "terminated"]
        found = 0
        for emp in terminated:
            email = emp["email"]
            if email in okta_active:
                term_date = parse_date(emp.get("termination_date"))
                days_since = days_ago(term_date)
                self._fail(
                    "CC6.2",
                    f"[HR] Terminated user still ACTIVE: {email}",
                    {
                        "email": email,
                        "name": emp["name"],
                        "termination_date": emp.get("termination_date"),
                        "days_since_termination": days_since,
                        "okta_status": okta_active[email].get("status"),
                        "finding": (
                            f"Employee terminated {days_since} days ago "
                            f"but Okta account is still ACTIVE"
                        ),
                    },
                    "CRITICAL",
                )
                found += 1
        if found == 0:
            print("  ✅ Нет уволенных сотрудников с активным доступом")

    def check_ghost_accounts(self, okta_active: dict, roster: list):
        """CC6.2: аккаунты в Okta, которых нет в HR-реестре."""
        print("── Проверка 2: Ghost accounts (CC6.2) ──")
        roster_emails = {e["email"] for e in roster}
        # Исключаем системные/сервисные аккаунты
        service_suffixes = (".service", ".bot", ".api", "noreply")
        found = 0
        for email, user in okta_active.items():
            if any(email.endswith(s) or s in email for s in service_suffixes):
                continue
            if email not in roster_emails:
                created = parse_date(user.get("created"))
                self._fail(
                    "CC6.2",
                    f"[HR] Ghost account — not in HR roster: {email}",
                    {
                        "email": email,
                        "okta_status": user.get("status"),
                        "okta_created": user.get("created"),
                        "days_in_okta": days_ago(created),
                        "finding": "User exists in Okta but has no record in HR roster",
                    },
                    "HIGH",
                )
                found += 1
        if found == 0:
            print("  ✅ Все Okta-аккаунты соответствуют HR-реестру")

    def check_contractor_expiry(self, okta_all: dict, roster: list):
        """CC9.2: подрядчики с истёкшим контрактом, но активным доступом."""
        print("── Проверка 3: Contractor expiry (CC9.2) ──")
        contractors = [e for e in roster if e.get("employment_type") == "contractor"]
        found = 0
        for emp in contractors:
            email = emp["email"]
            end_date = parse_date(emp.get("contract_end_date"))
            if not end_date:
                continue
            days_overdue = days_ago(end_date)
            if days_overdue is None or days_overdue <= 0:
                continue
            # Контракт истёк — проверяем есть ли аккаунт в Okta
            if email in okta_all:
                okta_status = okta_all[email].get("status", "UNKNOWN")
                if okta_status in ("ACTIVE", "STAGED", "PROVISIONED"):
                    self._fail(
                        "CC9.2",
                        f"[HR] Contractor access not revoked: {email}",
                        {
                            "email": email,
                            "name": emp["name"],
                            "contract_end_date": emp.get("contract_end_date"),
                            "days_overdue": days_overdue,
                            "okta_status": okta_status,
                            "finding": (
                                f"Contractor contract expired {days_overdue} days ago "
                                f"but Okta account is {okta_status}"
                            ),
                        },
                        "HIGH",
                    )
                    found += 1
        if found == 0:
            print("  ✅ Все контракты актуальны или доступ своевременно отозван")

    def check_training_overdue(self, roster: list):
        """CC1.4: сотрудники без обучения более 30 дней с даты найма."""
        print("── Проверка 4: Security training overdue (CC1.4) ──")
        found = 0
        for emp in roster:
            if emp.get("status") == "terminated":
                continue
            if emp.get("training_completed"):
                continue
            hire_date = parse_date(emp.get("hire_date"))
            days_employed = days_ago(hire_date)
            if days_employed is None or days_employed <= TRAINING_GRACE_DAYS:
                continue
            self._fail(
                "CC1.4",
                f"[HR] Security training overdue: {emp['email']}",
                {
                    "email": emp["email"],
                    "name": emp["name"],
                    "role": emp["role"],
                    "hire_date": emp.get("hire_date"),
                    "days_employed": days_employed,
                    "grace_days": TRAINING_GRACE_DAYS,
                    "finding": (
                        f"Employee hired {days_employed} days ago "
                        f"has not completed security awareness training "
                        f"(limit: {TRAINING_GRACE_DAYS} days)"
                    ),
                },
                "HIGH",
            )
            found += 1
        if found == 0:
            print(f"  ✅ Все активные сотрудники прошли обучение в течение {TRAINING_GRACE_DAYS} дней")

    def check_dormant_accounts(self, okta_active: dict, roster: list):
        """CC6.2: активные аккаунты без входа более 90 дней."""
        print("── Проверка 5: Dormant accounts (CC6.2) ──")
        roster_map = {e["email"]: e for e in roster}
        found = 0
        for email, user in okta_active.items():
            last_login_str = user.get("lastLogin")
            if not last_login_str:
                # Никогда не логинился
                created = parse_date(user.get("created"))
                days_since_create = days_ago(created)
                if days_since_create and days_since_create > DORMANT_DAYS:
                    emp = roster_map.get(email, {})
                    self._fail(
                        "CC6.2",
                        f"[HR] Dormant account (never logged in): {email}",
                        {
                            "email": email,
                            "name": emp.get("name", "Unknown"),
                            "okta_created": user.get("created"),
                            "days_since_creation": days_since_create,
                            "last_login": None,
                            "finding": (
                                f"Account created {days_since_create} days ago "
                                f"but user has never logged in"
                            ),
                        },
                        "MEDIUM",
                    )
                    found += 1
                continue

            last_login = parse_date(last_login_str)
            idle_days = days_ago(last_login)
            if idle_days and idle_days > DORMANT_DAYS:
                emp = roster_map.get(email, {})
                self._fail(
                    "CC6.2",
                    f"[HR] Dormant account ({idle_days}d inactive): {email}",
                    {
                        "email": email,
                        "name": emp.get("name", "Unknown"),
                        "last_login": last_login_str,
                        "idle_days": idle_days,
                        "threshold_days": DORMANT_DAYS,
                        "finding": (
                            f"Account has not been used for {idle_days} days "
                            f"(threshold: {DORMANT_DAYS} days)"
                        ),
                    },
                    "MEDIUM",
                )
                found += 1
        if found == 0:
            print(f"  ✅ Нет dormant-аккаунтов (порог: {DORMANT_DAYS} дней)")

def main(controls_map: dict | None = None):
    # Load controls_map.json if not provided
    if controls_map is None:
        if not os.path.exists(CONTROLS_MAP_FILE):
            print(f"Error: {CONTROLS_MAP_FILE} not found. Run controls_seed.py first.")
            return
        with open(CONTROLS_MAP_FILE) as f:
            controls_map = json.load(f)

    print(f"\n{'='*60}")
    print(f" SOC 2 HR COMPLIANCE SCAN — {COMPANY_NAME}")
    print(f" {date.today()}")
    print(f"{'='*60}\n")

    agent = HRAgent(controls_map, EVIDENCE_TRACKER_URL, SLACK_WEBHOOK_URL)
    try:
        agent.run()
    except ValueError as e:
        print(f"[ERROR] {e}")
        return

    # Итог
    print(f"{'='*60}")
    print(f" ИТОГ HR AUDIT")
    print(f"{'='*60}")
    for code, status in agent.results.items():
        icon = "✅" if status == "PASS" else "❌"
        print(f"  {icon} {code}: {status} — {HRAgent.CONTROLS[code]}")
    print(f"\n  Всего нарушений: {len(agent.findings)}")
    critical = sum(1 for f in agent.findings if f.severity == "CRITICAL")
    high = sum(1 for f in agent.findings if f.severity == "HIGH")
    medium = sum(1 for f in agent.findings if f.severity == "MEDIUM")
    if agent.findings:
        print(f"  CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}")
    print(f"\n  Evidence → {EVIDENCE_TRACKER_URL}/docs (source=HR_AUDIT)")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
