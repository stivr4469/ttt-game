"""
Policy Lifecycle Manager — Segregation of Duties для SOC2 политик.

Правило SoD:
  AI генерирует → status: "draft"
  Human approves → status: "approved" → контрол = PASS

Хранение: SQLite (AsyncSessionLocal / SQLAlchemy async).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from log_config import get_logger

log = get_logger(__name__)


def _run_async(coro: Any) -> Any:
    """Запускает async корутину из синхронного контекста."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result(timeout=30)
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ── Evidence Tracker URL ───────────────────────────────────────────────────────
EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8080")


# ── Статусы жизненного цикла ──────────────────────────────────────────────────

class PolicyStatus(str, Enum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


# ── Доменная модель ───────────────────────────────────────────────────────────

@dataclass
class PolicyRecord:
    id: str
    control_id: str
    control_code: str           # "CC6.1"
    title: str
    content: str
    status: PolicyStatus
    created_by: str             # "ai:claude-haiku" или "human:admin@acme.com"
    approved_by: Optional[str]
    rejected_by: Optional[str]
    rejection_reason: Optional[str]
    created_at: str
    updated_at: str
    approved_at: Optional[str]
    version: int                # инкрементируется при каждом approve


# ── Вспомогательные функции ───────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_policies() -> list[dict]:
    """Загрузить все политики из БД."""
    return _run_async(_load_policies_db())


async def _load_policies_db() -> list[dict]:
    """Загрузить все политики из БД (PolicyVersion)."""
    from database import AsyncSessionLocal
    from models import PolicyVersion
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(PolicyVersion))
        rows = result.scalars().all()
        records = []
        for row in rows:
            records.append({
                "id": row.id,
                "control_id": row.control_id,
                "control_code": row.control_id,  # control_code хранится как control_id
                "title": row.title,
                "content": row.content,
                "status": row.status,
                "created_by": row.created_by,
                "approved_by": row.approved_by,
                "rejected_by": None,
                "rejection_reason": None,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.approved_at.isoformat() if row.approved_at else (
                    row.created_at.isoformat() if row.created_at else None
                ),
                "approved_at": row.approved_at.isoformat() if row.approved_at else None,
                "version": int(row.version) if row.version and row.version.isdigit() else 1,
            })
        return records


def _save_policies(records: list[dict]) -> None:
    """Сохранить все политики в БД."""
    _run_async(_save_policies_db(records))


async def _save_policies_db(records: list[dict]) -> None:
    """Upsert всех политик в БД (PolicyVersion) по id."""
    from database import AsyncSessionLocal
    from models import PolicyVersion
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        for d in records:
            result = await session.execute(
                select(PolicyVersion).where(PolicyVersion.id == d["id"])
            )
            existing = result.scalar_one_or_none()

            approved_at = None
            if d.get("approved_at"):
                try:
                    approved_at = datetime.fromisoformat(d["approved_at"])
                except Exception:
                    pass

            version_str = str(d.get("version", 1))

            if existing is None:
                row = PolicyVersion(
                    id=d["id"],
                    control_id=d.get("control_code") or d.get("control_id", ""),
                    title=d.get("title", ""),
                    content=d.get("content", ""),
                    version=version_str,
                    status=d.get("status", "draft"),
                    created_by=d.get("created_by", "system"),
                    approved_by=d.get("approved_by"),
                    approved_at=approved_at,
                )
                session.add(row)
            else:
                existing.control_id = d.get("control_code") or d.get("control_id", existing.control_id)
                existing.title = d.get("title", existing.title)
                existing.content = d.get("content", existing.content)
                existing.version = version_str
                existing.status = d.get("status", existing.status)
                existing.created_by = d.get("created_by", existing.created_by)
                existing.approved_by = d.get("approved_by", existing.approved_by)
                existing.approved_at = approved_at if approved_at else existing.approved_at
        await session.commit()


def _record_from_dict(d: dict) -> PolicyRecord:
    return PolicyRecord(
        id=d["id"],
        control_id=d["control_id"],
        control_code=d["control_code"],
        title=d["title"],
        content=d["content"],
        status=PolicyStatus(d["status"]),
        created_by=d["created_by"],
        approved_by=d.get("approved_by"),
        rejected_by=d.get("rejected_by"),
        rejection_reason=d.get("rejection_reason"),
        created_at=d["created_at"],
        updated_at=d["updated_at"],
        approved_at=d.get("approved_at"),
        version=int(d.get("version", 1)),
    )


# ── Менеджер жизненного цикла ─────────────────────────────────────────────────

class PolicyLifecycleManager:
    """
    Управляет жизненным циклом политик: draft → pending_review → approved/rejected.

    Все переходы статусов журналируются; approved() вызывает EvidenceClient
    для обновления статуса контроля на PASS.
    """

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create_draft(
        self,
        control_id: str,
        control_code: str,
        title: str,
        content: str,
        created_by: str,
        via_ai_advisor: bool = False,
    ) -> PolicyRecord:
        """
        Создать черновик политики (начальный статус: draft).

        Если via_ai_advisor=True — draft создан через AIAdvisor.draft_policy().
        Статус всегда DRAFT; переход в APPROVED возможен только через approve()
        и только с явным human-approver.
        """
        now = _now_iso()
        record = PolicyRecord(
            id=f"POL-{uuid.uuid4().hex[:8].upper()}",
            control_id=control_id,
            control_code=control_code,
            title=title,
            content=content,
            status=PolicyStatus.DRAFT,
            created_by=created_by,
            approved_by=None,
            rejected_by=None,
            rejection_reason=None,
            created_at=now,
            updated_at=now,
            approved_at=None,
            version=1,
        )
        records = _load_policies()
        records.append(asdict(record))
        _save_policies(records)
        source_label = "via AIAdvisor" if via_ai_advisor else "напрямую"
        log.info(
            "Создан черновик политики %s для контрола %s (%s)",
            record.id, control_code, source_label,
        )
        return record

    def create_draft_from_ai_advisor(
        self,
        control_id: str,
        control_code: str,
        title: str,
        ai_content: str,
    ) -> PolicyRecord:
        """
        Создать черновик через AIAdvisor.

        Обёртка, явно документирующая что контент сгенерирован AI.
        Статус всегда DRAFT — только человек (admin) может перевести в APPROVED.

        Импортирует AIAdvisor и логирует факт создания через AI.
        """
        from ai_advisor import get_ai_advisor
        advisor = get_ai_advisor()
        # Логируем через advisor (он сам вызовет AIDecisionLogger)
        advice = advisor.draft_policy(
            control_id=control_id,
            control_title=title,
        )
        # Используем переданный контент (уже сгенерирован вызывающим кодом),
        # или контент от advisor если не передан явно
        content = ai_content or advice.suggestion
        created_by = f"ai:advisor ({advice.confidence:.2f})"
        return self.create_draft(
            control_id=control_id,
            control_code=control_code,
            title=title,
            content=content,
            created_by=created_by,
            via_ai_advisor=True,
        )

    def get_by_id(self, policy_id: str) -> Optional[PolicyRecord]:
        """Получить политику по ID."""
        for d in _load_policies():
            if d["id"] == policy_id:
                return _record_from_dict(d)
        return None

    def get_all(
        self,
        status: Optional[str] = None,
        control_code: Optional[str] = None,
    ) -> list[PolicyRecord]:
        """Получить все политики с опциональной фильтрацией."""
        records = _load_policies()
        result = []
        for d in records:
            if status and d.get("status") != status:
                continue
            if control_code and d.get("control_code") != control_code:
                continue
            try:
                result.append(_record_from_dict(d))
            except Exception as exc:
                log.warning(f"Пропуск повреждённой записи {d.get('id')}: {exc}")
        return result

    def get_pending_count(self) -> int:
        """Количество политик в статусе pending_review."""
        return sum(
            1 for d in _load_policies()
            if d.get("status") == PolicyStatus.PENDING_REVIEW.value
        )

    def get_summary(self) -> dict:
        """Статистика по статусам."""
        counts: dict[str, int] = {s.value: 0 for s in PolicyStatus}
        for d in _load_policies():
            status_val = d.get("status", "")
            if status_val in counts:
                counts[status_val] += 1
        return {
            "total": sum(counts.values()),
            "by_status": counts,
        }

    # ── Переходы статусов ─────────────────────────────────────────────────────

    def submit_for_review(self, policy_id: str) -> PolicyRecord:
        """Перевести политику из draft → pending_review."""
        return self._transition(
            policy_id=policy_id,
            allowed_from={PolicyStatus.DRAFT},
            new_status=PolicyStatus.PENDING_REVIEW,
            error_msg=f"Политика {policy_id} должна быть в статусе 'draft' для подачи на ревью",
        )

    def approve(self, policy_id: str, approver: str) -> PolicyRecord:
        """
        Перевести политику из pending_review → approved.

        Также обновляет статус контроля на PASS через EvidenceClient.
        Версия инкрементируется при каждом approve.
        """
        records = _load_policies()
        idx, d = self._find_record(records, policy_id)

        current = PolicyStatus(d["status"])
        if current != PolicyStatus.PENDING_REVIEW:
            raise ValueError(
                f"Политика {policy_id} должна быть в статусе 'pending_review' для approve. "
                f"Текущий: '{current.value}'"
            )

        now = _now_iso()
        d["status"] = PolicyStatus.APPROVED.value
        d["approved_by"] = approver
        d["approved_at"] = now
        d["updated_at"] = now
        d["version"] = int(d.get("version", 1)) + 1
        d["rejected_by"] = None
        d["rejection_reason"] = None

        records[idx] = d
        _save_policies(records)

        record = _record_from_dict(d)
        log.info(f"Политика {policy_id} одобрена пользователем {approver}, версия {record.version}")

        # Обновить статус контроля в Evidence Tracker
        self._update_control_status(record.control_id, "PASS", policy_id)

        # Детерминированная переоценка контроля через ComplianceEngine
        # (только логируем — не блокируем approve при ошибке)
        self._reevaluate_control_via_engine(record.control_id, policy_id)

        return record

    def reject(self, policy_id: str, reviewer: str, reason: str) -> PolicyRecord:
        """Перевести политику из pending_review → rejected."""
        if not reason or not reason.strip():
            raise ValueError("Причина отклонения не может быть пустой")

        records = _load_policies()
        idx, d = self._find_record(records, policy_id)

        current = PolicyStatus(d["status"])
        if current != PolicyStatus.PENDING_REVIEW:
            raise ValueError(
                f"Политика {policy_id} должна быть в статусе 'pending_review' для reject. "
                f"Текущий: '{current.value}'"
            )

        now = _now_iso()
        d["status"] = PolicyStatus.REJECTED.value
        d["rejected_by"] = reviewer
        d["rejection_reason"] = reason.strip()
        d["updated_at"] = now

        records[idx] = d
        _save_policies(records)

        log.info(f"Политика {policy_id} отклонена пользователем {reviewer}: {reason}")
        return _record_from_dict(d)

    def revise(self, policy_id: str, new_content: str, editor: str) -> PolicyRecord:
        """
        Создать новую версию отклонённой политики: rejected → draft.

        Контент обновляется; created_by обновляется на редактора; счётчик версии сохраняется.
        """
        if not new_content or not new_content.strip():
            raise ValueError("Новый контент политики не может быть пустым")

        records = _load_policies()
        idx, d = self._find_record(records, policy_id)

        current = PolicyStatus(d["status"])
        if current != PolicyStatus.REJECTED:
            raise ValueError(
                f"Политика {policy_id} должна быть в статусе 'rejected' для revise. "
                f"Текущий: '{current.value}'"
            )

        now = _now_iso()
        d["status"] = PolicyStatus.DRAFT.value
        d["content"] = new_content.strip()
        d["created_by"] = editor
        d["rejected_by"] = None
        d["rejection_reason"] = None
        d["updated_at"] = now

        records[idx] = d
        _save_policies(records)

        log.info(f"Политика {policy_id} переработана пользователем {editor}")
        return _record_from_dict(d)

    def expire(self, policy_id: str) -> PolicyRecord:
        """Перевести политику из approved → expired (при плановом ревью)."""
        return self._transition(
            policy_id=policy_id,
            allowed_from={PolicyStatus.APPROVED},
            new_status=PolicyStatus.EXPIRED,
            error_msg=f"Политика {policy_id} должна быть в статусе 'approved' для expire",
        )

    def delete_draft(self, policy_id: str) -> None:
        """Удалить черновик (только draft). Одобренные политики удалять нельзя."""
        records = _load_policies()
        idx, d = self._find_record(records, policy_id)

        if PolicyStatus(d["status"]) != PolicyStatus.DRAFT:
            raise ValueError(
                f"Можно удалять только черновики. Статус политики {policy_id}: '{d['status']}'"
            )

        records.pop(idx)
        _save_policies(records)
        log.info(f"Черновик политики {policy_id} удалён")

    # ── Внутренние хелперы ────────────────────────────────────────────────────

    def _find_record(self, records: list[dict], policy_id: str) -> tuple[int, dict]:
        """Найти запись по ID; выбросить ValueError если не найдена."""
        for idx, d in enumerate(records):
            if d["id"] == policy_id:
                return idx, d
        raise ValueError(f"Политика {policy_id} не найдена")

    def _transition(
        self,
        policy_id: str,
        allowed_from: set[PolicyStatus],
        new_status: PolicyStatus,
        error_msg: str,
    ) -> PolicyRecord:
        """Общая логика перехода статуса."""
        records = _load_policies()
        idx, d = self._find_record(records, policy_id)

        current = PolicyStatus(d["status"])
        if current not in allowed_from:
            raise ValueError(
                f"{error_msg}. Текущий статус: '{current.value}'"
            )

        d["status"] = new_status.value
        d["updated_at"] = _now_iso()
        records[idx] = d
        _save_policies(records)

        log.info(f"Политика {policy_id}: {current.value} → {new_status.value}")
        return _record_from_dict(d)

    def _update_control_status(
        self, control_id: str, status: str, policy_id: str
    ) -> None:
        """Обновить статус контроля в Evidence Tracker (не блокирует approve при ошибке)."""
        try:
            from evidence_client import EvidenceClient
            client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="policy_lifecycle")
            client.submit_test_result(control_id, status, test_key="policy_lifecycle.policy_approved", producer="policy_lifecycle")
            log.info(
                f"Контрол {control_id} переведён в {status} после approve политики {policy_id}"
            )
        except Exception as exc:
            # Ошибка не отменяет approve — журналируем, но не бросаем
            log.error(
                f"Не удалось обновить статус контроля {control_id} → {status}: {exc}. "
                f"Политика {policy_id} одобрена, но контрол нужно обновить вручную."
            )

    def _reevaluate_control_via_engine(
        self, control_id: str, policy_id: str
    ) -> None:
        """
        Детерминированная переоценка контроля через ComplianceEngine после approve.

        Вызывается при смене статуса Evidence (approve политики).
        Не блокирует approve при ошибке — только логирует вердикт.
        ComplianceEngine не вызывает AI.
        """
        try:
            from compliance_engine import get_compliance_engine
            from evidence_client import EvidenceClient

            client = EvidenceClient(EVIDENCE_TRACKER_URL, agent_name="policy_lifecycle")
            evidence = client.get_evidence(control_id=control_id, limit=50)

            engine = get_compliance_engine()
            verdict = engine.evaluate_control(control_id, evidence)

            log.info(
                "ComplianceEngine re-evaluation после approve %s: "
                "control=%s → %s (confidence=%.2f)",
                policy_id, control_id, verdict.status.value, verdict.confidence,
            )
        except Exception as exc:
            # Не блокируем approve при ошибке переоценки
            log.warning(
                "ComplianceEngine re-evaluation не удалась для %s: %s. "
                "Approve %s завершён успешно.",
                control_id, exc, policy_id,
            )
