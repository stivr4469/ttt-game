"""
Миграция данных из JSON-файлов в БД (SQLite/PostgreSQL).

Читает все существующие JSON-файлы и вставляет данные через репозитории.
JSON-файлы НЕ удаляются — backward compatibility сохраняется.

Запуск:
  python db_migration.py                    # мигрирует всё
  python db_migration.py --only vendors     # только вендоры
  python db_migration.py --dry-run          # без записи в БД

Переменные окружения:
  DATABASE_URL — если не задан, использует SQLite compliance.db
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal, init_db
from db_repository import (
    AuditEventRepository,
    ControlRepository,
    EvidenceRepository,
    RiskRepository,
    VendorRepository,
    PolicyRepository,
    TrainingRepository,
)

# ── Корень проекта и пути к JSON-файлам ──────────────────────────────────────

PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"

_JSON_PATHS = {
    "risk_register":         PROJECT_ROOT / "risk_register.json",
    "training_completions":  PROJECT_ROOT / "training_completions.json",
    "vendors":               DATA_DIR / "vendors.json",
    "vendor_assessments":    DATA_DIR / "vendor_assessments.json",
    "policies":              DATA_DIR / "policies.json",
}


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _load_json(path: Path) -> Any:
    """Загружает JSON-файл. Возвращает [] если файл не существует."""
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Ошибка чтения {path}: {e}")
        return []


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    """Парсит ISO-строку в datetime с timezone. None если не удалось."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


# ── Функции миграции по сущностям ─────────────────────────────────────────────

async def migrate_risk_register(session: AsyncSession, dry_run: bool = False) -> int:
    """Мигрирует risk_register.json → таблицу risk_entry."""
    risks: List[Dict] = _load_json(_JSON_PATHS["risk_register"])
    if not risks:
        print("[INFO] risk_register.json пуст или не найден, пропускаем")
        return 0

    repo = RiskRepository(session)
    audit_repo = AuditEventRepository(session)
    migrated = 0

    for risk in risks:
        risk_id = risk.get("id", "")
        if not risk_id:
            continue
        # Пропускаем если уже существует
        existing = await repo.get(risk_id)
        if existing:
            continue

        if not dry_run:
            await repo.create(
                risk_id=risk_id,
                title=risk.get("title", ""),
                likelihood=int(risk.get("likelihood", 3)),
                impact=int(risk.get("impact", 3)),
                score=int(risk.get("risk_score", 9)),
                status=risk.get("status", "open"),
                control_id=risk.get("control_id"),
                description=risk.get("description", ""),
                source=risk.get("source", "manual"),
                category=risk.get("category", "operational"),
                owner=risk.get("owner"),
                treatment=risk.get("treatment", "mitigate"),
                treatment_plan=risk.get("treatment_plan", ""),
                jira_ticket=risk.get("jira_ticket"),
                target_date=risk.get("target_date"),
            )
            await audit_repo.append(
                event_type="risk.migrated",
                entity_type="risk",
                entity_id=risk_id,
                actor="migration",
                payload={"source": "risk_register.json"},
            )
        migrated += 1

    print(f"[MIGRATE] risk_register: {migrated} записей{'(dry run)' if dry_run else ''}")
    return migrated


async def migrate_vendors(session: AsyncSession, dry_run: bool = False) -> int:
    """Мигрирует data/vendors.json → таблицу vendor."""
    vendors: List[Dict] = _load_json(_JSON_PATHS["vendors"])
    if not vendors:
        print("[INFO] data/vendors.json пуст или не найден, пропускаем")
        return 0

    repo = VendorRepository(session)
    audit_repo = AuditEventRepository(session)
    migrated = 0

    for vendor in vendors:
        vendor_id = vendor.get("id", "")
        if not vendor_id:
            continue

        existing = await repo.get(vendor_id)
        if existing:
            continue

        # Маппинг criticality → tier
        criticality = vendor.get("criticality", vendor.get("risk_level", "medium")) or "medium"

        if not dry_run:
            # Основные поля вынесены, остальные хранятся в data (JSON)
            extra_data = {
                k: v for k, v in vendor.items()
                if k not in ("id", "name", "dpa_signed", "last_review_date", "status", "criticality")
            }
            await repo.create(
                vendor_id=vendor_id,
                name=vendor.get("name", ""),
                tier=criticality,
                status=vendor.get("status", "pending"),
                dpa_signed=bool(vendor.get("dpa_signed", False)),
                last_review_date=vendor.get("last_review_date"),
                data=extra_data,
            )
            await audit_repo.append(
                event_type="vendor.migrated",
                entity_type="vendor",
                entity_id=vendor_id,
                actor="migration",
                payload={"source": "data/vendors.json"},
            )
        migrated += 1

    print(f"[MIGRATE] vendors: {migrated} записей{'(dry run)' if dry_run else ''}")
    return migrated


async def migrate_training(session: AsyncSession, dry_run: bool = False) -> int:
    """Мигрирует training_completions.json → таблицу training_completion."""
    raw: Dict = _load_json(_JSON_PATHS["training_completions"])
    if not raw or not isinstance(raw, dict):
        print("[INFO] training_completions.json пуст или не найден, пропускаем")
        return 0

    repo = TrainingRepository(session)
    migrated = 0

    # Структура: {"email@acme.com": {"course_id": {...}}}
    for employee_id, courses in raw.items():
        if not isinstance(courses, dict):
            continue
        for course_id, course_data in courses.items():
            if not isinstance(course_data, dict):
                continue

            completed_at = _parse_dt(course_data.get("completed_at"))

            if not dry_run:
                await repo.create(
                    employee_id=employee_id,
                    course_id=course_id,
                    completed_at=completed_at,
                    certificate_url=course_data.get("certificate_id"),
                    extra=course_data,
                )
            migrated += 1

    print(f"[MIGRATE] training_completions: {migrated} записей{'(dry run)' if dry_run else ''}")
    return migrated


async def migrate_policies(session: AsyncSession, dry_run: bool = False) -> int:
    """Мигрирует data/policies.json → таблицу policy_draft."""
    policies: List[Dict] = _load_json(_JSON_PATHS["policies"])
    if not policies:
        print("[INFO] data/policies.json пуст или не найден, пропускаем")
        return 0

    repo = PolicyRepository(session)
    migrated = 0

    for policy in policies:
        policy_id = policy.get("id", "")
        if not policy_id:
            continue

        existing = await repo.get(policy_id)
        if existing:
            continue

        if not dry_run:
            await repo.create(
                policy_id=policy_id,
                control_id=policy.get("control_id", ""),
                title=policy.get("title", ""),
                content=policy.get("content", ""),
                status=policy.get("status", "draft"),
                created_by=policy.get("created_by", "migration"),
                approved_by=policy.get("approved_by"),
            )
        migrated += 1

    print(f"[MIGRATE] policies: {migrated} записей{'(dry run)' if dry_run else ''}")
    return migrated


async def migrate_all(dry_run: bool = False) -> None:
    """
    Главная функция миграции: инициализирует БД и мигрирует все сущности.
    """
    print(f"[MIGRATE] Начало миграции (dry_run={dry_run})")

    # Создаём таблицы если нет
    if not dry_run:
        await init_db()
        print("[MIGRATE] Схема БД инициализирована")

    async with AsyncSessionLocal() as session:
        total = 0
        total += await migrate_risk_register(session, dry_run)
        total += await migrate_vendors(session, dry_run)
        total += await migrate_training(session, dry_run)
        total += await migrate_policies(session, dry_run)

        if not dry_run:
            await session.commit()
            print(f"[MIGRATE] Зафиксировано {total} записей в БД")
        else:
            print(f"[MIGRATE] DRY RUN: было бы мигрировано {total} записей")


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Миграция JSON-данных в БД")
    parser.add_argument(
        "--only",
        choices=["risks", "vendors", "training", "policies"],
        help="Мигрировать только указанную сущность",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Не записывать в БД, только считать",
    )
    return parser.parse_args()


async def _run_selective(only: str, dry_run: bool) -> None:
    """Запускает миграцию только для указанной сущности."""
    if not dry_run:
        await init_db()

    async with AsyncSessionLocal() as session:
        if only == "risks":
            await migrate_risk_register(session, dry_run)
        elif only == "vendors":
            await migrate_vendors(session, dry_run)
        elif only == "training":
            await migrate_training(session, dry_run)
        elif only == "policies":
            await migrate_policies(session, dry_run)

        if not dry_run:
            await session.commit()


if __name__ == "__main__":
    args = _parse_args()
    if args.only:
        asyncio.run(_run_selective(args.only, args.dry_run))
    else:
        asyncio.run(migrate_all(args.dry_run))
