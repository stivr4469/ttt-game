#!/usr/bin/env python3
"""Одноразовая миграция данных из JSON-файлов в SQLite (compliance.db).

Идемпотентна: повторный запуск не дублирует записи (on_conflict_do_nothing).
Ошибка в одном JSON-файле не прерывает миграцию остальных.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from database import AsyncSessionLocal, init_db
from models import (
    AccessReviewDecision,
    HREmployee,
    PentestReport,
    QuestionnaireResponse,
    RiskEntry,
    TrainingCompletionDetail,
    Vendor,
)

ROOT = Path(__file__).parent


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _load(path: str) -> dict | list | None:
    """Загружает JSON-файл. Возвращает None если файл не найден или пустой."""
    p = ROOT / path
    if not p.exists():
        print(f"  SKIP {path} (not found)")
        return None
    raw = p.read_text(encoding="utf-8").strip()
    if not raw:
        print(f"  SKIP {path} (empty file)")
        return None
    try:
        return json.loads(raw)
    except Exception as e:
        print(f"  ERROR {path}: {e}")
        return None


def _new_uuid() -> str:
    return str(uuid.uuid4())


def _parse_dt(value: Any) -> datetime | None:
    """Парсит ISO-строку в datetime с timezone. Возвращает None при ошибке."""
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


# ── Миграция рисков ───────────────────────────────────────────────────────────

async def migrate_risks(session) -> None:
    print("\n[1/7] Migrating risk_register.json → RiskEntry...")
    data = _load("risk_register.json")
    if data is None:
        return

    # Поддержка двух форматов: список или {"risks": [...]}
    rows: list[dict] = data if isinstance(data, list) else data.get("risks", [])
    if not rows:
        print("  SKIP: no records found")
        return

    inserted = skipped = errors = 0
    for row in rows:
        try:
            stmt = sqlite_insert(RiskEntry).values(
                id=row["id"],
                control_id=row.get("control_id"),
                title=row.get("title", ""),
                description=row.get("description", ""),
                source=row.get("source", "manual"),
                likelihood=int(row.get("likelihood", 3)),
                impact=int(row.get("impact", 3)),
                # JSON-файл хранит поле как risk_score, модель — score
                score=int(row.get("score", row.get("risk_score", 9))),
                category=row.get("category", "operational"),
                owner=row.get("owner"),
                treatment=row.get("treatment", "mitigate"),
                treatment_plan=row.get("treatment_plan", ""),
                status=row.get("status", "open"),
                jira_ticket=row.get("jira_ticket"),
                target_date=row.get("target_date"),
                created_at=_parse_dt(row.get("created_at")) or datetime.now(timezone.utc),
                updated_at=_parse_dt(row.get("updated_at")) or datetime.now(timezone.utc),
            ).on_conflict_do_nothing(index_elements=["id"])
            result = await session.execute(stmt)
            if result.rowcount:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  ERROR row {row.get('id')}: {e}")
            errors += 1

    print(f"  inserted={inserted}, skipped(exist)={skipped}, errors={errors}")


# ── Миграция вендоров ─────────────────────────────────────────────────────────

async def migrate_vendors(session) -> None:
    print("\n[2/7] Migrating vendors.json → Vendor...")
    # Пробуем оба пути
    data = _load("data/vendors.json") or _load("vendors.json")
    if data is None:
        return

    rows: list[dict] = data if isinstance(data, list) else data.get("vendors", [])
    if not rows:
        print("  SKIP: no records found")
        return

    inserted = skipped = errors = 0
    # Поля, которые идут напрямую в колонки модели
    DIRECT_FIELDS = {"id", "name", "tier", "status", "dpa_signed", "last_review_date"}

    for row in rows:
        try:
            # Всё остальное складываем в data (JSON-колонка)
            extra: dict[str, Any] = {k: v for k, v in row.items() if k not in DIRECT_FIELDS}

            stmt = sqlite_insert(Vendor).values(
                id=row["id"],
                name=row.get("name", ""),
                tier=row.get("tier", row.get("criticality", "medium")),
                status=row.get("status", "pending"),
                dpa_signed=bool(row.get("dpa_signed", False)),
                last_review_date=row.get("last_review_date"),
                data=extra or None,
            ).on_conflict_do_nothing(index_elements=["id"])
            result = await session.execute(stmt)
            if result.rowcount:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  ERROR row {row.get('id')}: {e}")
            errors += 1

    print(f"  inserted={inserted}, skipped(exist)={skipped}, errors={errors}")


# ── Миграция training completions ─────────────────────────────────────────────

async def migrate_training(session) -> None:
    print("\n[3/7] Migrating training_completions.json → TrainingCompletionDetail...")
    data = _load("training_completions.json")
    if data is None:
        return

    if not isinstance(data, dict):
        print("  ERROR: expected dict {email: {course_id: {...}}}")
        return

    inserted = skipped = errors = 0
    for employee_email, courses in data.items():
        if not isinstance(courses, dict):
            continue
        for course_id, details in courses.items():
            if not isinstance(details, dict):
                continue
            try:
                stmt = sqlite_insert(TrainingCompletionDetail).values(
                    id=_new_uuid(),
                    employee_email=employee_email,
                    course_id=course_id,
                    course_title=details.get("course_title", ""),
                    status=details.get("status", "not_started"),
                    score=details.get("score"),
                    certificate_id=details.get("certificate_id"),
                    attempts=int(details.get("attempts", 1)),
                    completed_at=_parse_dt(details.get("completed_at")),
                    created_at=datetime.now(timezone.utc),
                ).on_conflict_do_nothing(
                    index_elements=None,
                    # Уникальное ограничение по (employee_email, course_id)
                )
                result = await session.execute(stmt)
                if result.rowcount:
                    inserted += 1
                else:
                    skipped += 1
            except Exception as e:
                print(f"  ERROR {employee_email}/{course_id}: {e}")
                errors += 1

    print(f"  inserted={inserted}, skipped(exist)={skipped}, errors={errors}")


# ── Миграция access review decisions ─────────────────────────────────────────

async def migrate_access_review(session) -> None:
    print("\n[4/7] Migrating access_review_data.json → AccessReviewDecision...")
    data = _load("access_review_data.json")
    if data is None:
        return

    if not isinstance(data, dict):
        print("  ERROR: expected dict {user_id: {decision, reviewer, ...}}")
        return

    inserted = skipped = errors = 0
    for user_id, review in data.items():
        if not isinstance(review, dict):
            continue
        try:
            stmt = sqlite_insert(AccessReviewDecision).values(
                id=_new_uuid(),
                user_id=user_id,
                decision=review.get("decision", ""),
                reviewer=review.get("reviewer", ""),
                reason=review.get("reason", ""),
                decided_at=_parse_dt(review.get("decided_at")),
                created_at=datetime.now(timezone.utc),
            ).on_conflict_do_nothing(index_elements=["user_id"])
            result = await session.execute(stmt)
            if result.rowcount:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  ERROR user_id={user_id}: {e}")
            errors += 1

    print(f"  inserted={inserted}, skipped(exist)={skipped}, errors={errors}")


# ── Миграция pentest reports ──────────────────────────────────────────────────

async def migrate_pentest(session) -> None:
    print("\n[5/7] Migrating pentest_reports.json → PentestReport...")
    data = _load("pentest_reports.json")
    if data is None:
        return

    rows: list[dict] = data if isinstance(data, list) else data.get("reports", [])
    if not rows:
        print("  SKIP: no records found")
        return

    inserted = skipped = errors = 0
    for row in rows:
        try:
            stmt = sqlite_insert(PentestReport).values(
                id=row.get("id", _new_uuid()),
                title=row.get("title", ""),
                vendor=row.get("vendor", ""),
                test_type=row.get("test_type", "web_app"),
                start_date=row.get("start_date"),
                end_date=row.get("end_date"),
                scope=row.get("scope", ""),
                findings=row.get("findings"),
                status=row.get("status", "draft"),
                executive_summary=row.get("executive_summary", ""),
                created_at=_parse_dt(row.get("created_at")) or datetime.now(timezone.utc),
            ).on_conflict_do_nothing(index_elements=["id"])
            result = await session.execute(stmt)
            if result.rowcount:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  ERROR row {row.get('id')}: {e}")
            errors += 1

    print(f"  inserted={inserted}, skipped(exist)={skipped}, errors={errors}")


# ── Миграция questionnaire responses ─────────────────────────────────────────

async def migrate_questionnaires(session) -> None:
    print("\n[6/7] Migrating questionnaire_responses.json → QuestionnaireResponse...")
    data = _load("questionnaire_responses.json")
    if data is None:
        return

    rows: list[dict] = data if isinstance(data, list) else data.get("responses", [])
    if not rows:
        print("  SKIP: no records found")
        return

    inserted = skipped = errors = 0
    for row in rows:
        try:
            stmt = sqlite_insert(QuestionnaireResponse).values(
                id=row.get("id", _new_uuid()),
                questionnaire=row.get("questionnaire", "custom"),
                questionnaire_name=row.get("questionnaire_name", ""),
                requester=row.get("requester"),
                total_questions=int(row.get("total_questions", 0)),
                high_confidence=int(row.get("high_confidence", 0)),
                needs_review_count=int(row.get("needs_review_count", 0)),
                answers=row.get("answers"),
                generated_at=_parse_dt(row.get("generated_at")),
                created_at=datetime.now(timezone.utc),
            ).on_conflict_do_nothing(index_elements=["id"])
            result = await session.execute(stmt)
            if result.rowcount:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  ERROR row {row.get('id')}: {e}")
            errors += 1

    print(f"  inserted={inserted}, skipped(exist)={skipped}, errors={errors}")


# ── Миграция HR Roster ────────────────────────────────────────────────────────

async def migrate_hr(session) -> None:
    print("\n[7/7] Migrating hr_roster.json → HREmployee...")
    data = _load("hr_roster.json")
    if data is None:
        return

    # Поддержка структуры {"employees": [...]} и плоского списка
    if isinstance(data, dict):
        rows: list[dict] = data.get("employees", [])
    else:
        rows = data

    if not rows:
        print("  SKIP: no records found")
        return

    inserted = skipped = errors = 0
    for row in rows:
        try:
            # id может отсутствовать (как в текущем hr_roster.json — ключ email)
            emp_id = row.get("id") or _new_uuid()
            stmt = sqlite_insert(HREmployee).values(
                id=emp_id,
                email=row["email"],
                name=row.get("name", ""),
                role=row.get("role", ""),
                department=row.get("department", ""),
                hire_date=row.get("hire_date"),
                employment_type=row.get("employment_type", "full_time"),
                contract_end_date=row.get("contract_end_date"),
                termination_date=row.get("termination_date"),
                status=row.get("status", "active"),
                training_completed=bool(row.get("training_completed", False)),
                training_date=row.get("training_date"),
                notes=row.get("notes", ""),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            ).on_conflict_do_nothing(index_elements=["email"])
            result = await session.execute(stmt)
            if result.rowcount:
                inserted += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  ERROR email={row.get('email')}: {e}")
            errors += 1

    print(f"  inserted={inserted}, skipped(exist)={skipped}, errors={errors}")


# ── Точка входа ───────────────────────────────────────────────────────────────

async def main() -> None:
    print("=" * 60)
    print("JSON → SQLite migration (compliance.db)")
    print("=" * 60)

    print("\nInitializing DB schema...")
    await init_db()
    print("  DB schema ready.")

    async with AsyncSessionLocal() as session:
        try:
            await migrate_risks(session)
        except Exception as e:
            print(f"  FATAL migrate_risks: {e}")

        try:
            await migrate_vendors(session)
        except Exception as e:
            print(f"  FATAL migrate_vendors: {e}")

        try:
            await migrate_training(session)
        except Exception as e:
            print(f"  FATAL migrate_training: {e}")

        try:
            await migrate_access_review(session)
        except Exception as e:
            print(f"  FATAL migrate_access_review: {e}")

        try:
            await migrate_pentest(session)
        except Exception as e:
            print(f"  FATAL migrate_pentest: {e}")

        try:
            await migrate_questionnaires(session)
        except Exception as e:
            print(f"  FATAL migrate_questionnaires: {e}")

        try:
            await migrate_hr(session)
        except Exception as e:
            print(f"  FATAL migrate_hr: {e}")

        await session.commit()

    print("\n" + "=" * 60)
    print("Migration complete.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
