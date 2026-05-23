"""
SQLAlchemy ORM-модели для SOC2 Compliance Sandbox.

Покрывают: Evidence, ControlStatus, RiskEntry, Vendor,
PolicyDraft, TrainingCompletion, AuditEvent.

Все модели используют Base из database.py.
Типы: String(UUID), DateTime(timezone=True), JSON для гибких полей.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


# ── Вспомогательная функция: текущее время UTC ───────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Evidence ──────────────────────────────────────────────────────────────────

class Evidence(Base):
    """
    Доказательство выполнения контроля.
    Хранит контент (лог, скриншот текст, API ответ) привязанный к control_id.
    """
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    # confidence_score: 0.0–1.0, вычисляется evidence_confidence.py
    confidence_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        return f"<Evidence id={self.id} control={self.control_id} source={self.source}>"


# ── ControlStatus ─────────────────────────────────────────────────────────────

class ControlStatus(Base):
    """
    Текущий статус SOC2 контроля (PASS/FAIL/PARTIAL/UNKNOWN).
    Одна запись на control_id — upsert при обновлении.
    """
    __tablename__ = "control_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
    )
    # Кто обновил: "system", "human:admin@acme.com", "agent:okta"
    updated_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")

    def __repr__(self) -> str:
        return f"<ControlStatus control={self.control_id} status={self.status}>"


# ── RiskEntry ─────────────────────────────────────────────────────────────────

class RiskEntry(Base):
    """
    Запись в реестре рисков. Соответствует структуре risk_register.json.
    """
    __tablename__ = "risk_entry"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)  # "RISK-001"
    control_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="manual")
    # likelihood и impact: 1–5
    likelihood: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    impact: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=9)
    category: Mapped[str] = mapped_column(String(100), nullable=False, default="operational")
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    treatment: Mapped[str] = mapped_column(String(50), nullable=False, default="mitigate")
    treatment_plan: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open", index=True)
    jira_ticket: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    target_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
    )

    def __repr__(self) -> str:
        return f"<RiskEntry id={self.id} status={self.status} score={self.score}>"


# ── Vendor ────────────────────────────────────────────────────────────────────

class Vendor(Base):
    """
    Вендор в реестре третьих сторон. Соответствует data/vendors.json.
    Поле data хранит дополнительные поля (subprocessors, notes и т.д.) как JSON.
    """
    __tablename__ = "vendor"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)  # "VND-001"
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # tier: critical / high / medium / low
    tier: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    dpa_signed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_review_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    # Все остальные поля — гибкий JSON (category, risk_score, notes, etc.)
    data: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<Vendor id={self.id} name={self.name} status={self.status}>"


# ── PolicyDraft ───────────────────────────────────────────────────────────────

class PolicyDraft(Base):
    """
    Черновик политики в процессе согласования (SoD: AI → Human → Approved).
    Соответствует data/policies.json.
    """
    __tablename__ = "policy_draft"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # status: draft / pending_review / approved / rejected / expired
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft", index=True)
    # created_by: "ai:claude-haiku" или "human:admin@acme.com"
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )

    def __repr__(self) -> str:
        return f"<PolicyDraft id={self.id} control={self.control_id} status={self.status}>"


# ── TrainingCompletion ────────────────────────────────────────────────────────

class TrainingCompletion(Base):
    """
    Запись о прохождении обучения сотрудником.
    Соответствует training_completions.json.
    """
    __tablename__ = "training_completion"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    employee_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    course_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    certificate_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    # score, status и другие поля курса — в JSON
    extra: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:
        return f"<TrainingCompletion employee={self.employee_id} course={self.course_id}>"


# ── AuditEvent ────────────────────────────────────────────────────────────────

class AuditEvent(Base):
    """
    Immutable event log для event sourcing и audit trail.
    Append-only: записи никогда не удаляются и не изменяются.

    event_type: "evidence.created", "control.status_changed",
                "risk.created", "vendor.approved", "policy.approved", etc.
    """
    __tablename__ = "audit_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # entity_type: "evidence", "control", "risk", "vendor", "policy", "training"
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # actor: "system", "human:admin@acme.com", "agent:okta_agent"
    actor: Mapped[str] = mapped_column(String(200), nullable=False, default="system")
    # payload: любые данные события (before/after state, metadata)
    payload: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        index=True,
    )

    def __repr__(self) -> str:
        return (
            f"<AuditEvent id={self.id} type={self.event_type} "
            f"entity={self.entity_type}/{self.entity_id}>"
        )
