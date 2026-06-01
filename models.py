"""
SQLAlchemy ORM-модели для SOC2 Compliance Sandbox.

Покрывают: Evidence, ControlStatus, RiskEntry, Vendor,
PolicyDraft, TrainingCompletion, AuditEvent.

Все модели используют Base из database.py.
Типы: String(UUID), DateTime(timezone=True), JSON для гибких полей.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


# ── Вспомогательная функция: текущее время UTC ───────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Tenant ────────────────────────────────────────────────────────────────────

class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    slug: Mapped[str] = mapped_column(String(63), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class TenantSecret(Base):
    __tablename__ = "tenant_secrets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    value_enc: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_secret_tenant_key"),)


class TenantUser(Base):
    """Пользователи, привязанные к тенанту (замена хардкода USERS_DB в auth.py)."""
    __tablename__ = "tenant_users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    __table_args__ = (UniqueConstraint("tenant_id", "email", name="uq_tenant_user_email"),)


# ── Control ───────────────────────────────────────────────────────────────────

class Control(Base):
    """
    SOC2 контроль, привязанный к фреймворку (SOC2, ISO27001 и т.д.).
    Пара (framework_id, code) уникальна — один контрол не может быть
    задублирован внутри одного фреймворка.
    """
    __tablename__ = "control"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)  # "CC6.1", "CC7.2" и т.д.
    framework_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)
    __table_args__ = (
        UniqueConstraint("framework_id", "code", name="uq_control_framework_code"),
    )

    def __repr__(self) -> str:
        return f"<Control id={self.id} framework={self.framework_id} code={self.code}>"


# ── Evidence ──────────────────────────────────────────────────────────────────

class Evidence(Base):
    """
    Доказательство выполнения контроля.
    Хранит контент (лог, скриншот текст, API ответ) привязанный к control_id.
    """
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # control_id: NOT NULL + FK с CASCADE DELETE
    control_id: Mapped[str] = mapped_column(
        String(50),
        ForeignKey("control.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    # confidence_score: 0.0–1.0, вычисляется evidence_confidence.py
    confidence_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # content_hash: SHA-256 от content — используется для идемпотентного create
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True, default="")
    # sha256_hash: SHA-256 хэш артефакта/файла — для идемпотентности повторных запусков агентов
    sha256_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # previous_hash: content_hash предыдущей Evidence в цепочке для данного control_id.
    # None для первой записи в цепочке.
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    # chain_valid: True если previous_hash совпадает с content_hash предыдущей записи (или это первая)
    chain_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        server_default=func.now(),
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)
    __table_args__ = (
        UniqueConstraint("control_id", "source", "content_hash", name="uq_evidence_control_source_hash"),
        Index(
            "ix_evidence_control_source_sha256",
            "control_id", "source", "sha256_hash",
            unique=True,
        ),
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
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

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
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

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
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

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
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

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
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

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
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return (
            f"<AuditEvent id={self.id} type={self.event_type} "
            f"entity={self.entity_type}/{self.entity_id}>"
        )


# ── RemediationTicket ─────────────────────────────────────────────────────────

class RemediationTicket(Base):
    """Дедупликация Jira-тикетов по ремедиациям."""
    __tablename__ = "remediation_ticket"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    issue_key: Mapped[str] = mapped_column(String(50), nullable=False)
    jira_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)
    __table_args__ = (
        UniqueConstraint("control_id", name="uq_remediation_control"),
    )

    def __repr__(self) -> str:
        return f"<RemediationTicket control={self.control_id} issue={self.issue_key}>"


# ── EventQueue ────────────────────────────────────────────────────────────────

class EventQueue(Base):
    """
    Durable очередь compliance-событий для cross-process доставки.

    Проблема: EventBus — singleton в памяти одного процесса. Агенты в subprocess
    или Celery-воркерах не достигают in-memory handlers веб-приложения.

    Решение: publish() сохраняет каждое событие в эту таблицу. Polling-воркер
    (или Celery beat) читает pending-записи и доставляет их нужным handlers.

    Жизненный цикл записи:
      pending    → запись создана, ожидает обработки
      processing → воркер взял запись в работу
      done       → успешно обработано
      failed     → обработка завершилась ошибкой (см. поле error)
    """
    __tablename__ = "event_queue"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # entity_id: идентификатор сущности, которой касается событие (nullable для системных событий)
    entity_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    # payload: JSON-сериализованное тело события (включает все поля ComplianceEvent)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    # status: pending / processing / done / failed
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending", index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        index=True,
    )
    processed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # error: трейсбек или сообщение об ошибке при status=failed
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return (
            f"<EventQueue id={self.id} type={self.event_type} "
            f"status={self.status} entity={self.entity_id}>"
        )


# ── Remediation ───────────────────────────────────────────────────────────────

class Remediation(Base):
    """
    Запись о ремедиации контроля (remediations.json).
    Ключ — control_code (CC6.3, CC6.2, …).
    """
    __tablename__ = "remediation"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_code: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    jira_key: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    jira_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    finding: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    # priority: Critical / High / Medium / Low
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="Medium")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open", index=True)
    is_mock: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<Remediation control={self.control_code} status={self.status}>"


# ── CustomControl ─────────────────────────────────────────────────────────────

class CustomControl(Base):
    """
    Пользовательский контроль SOC2 (custom_controls.json, если появится).
    Хранит гибкие данные контроля как JSON.
    """
    __tablename__ = "custom_control"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    # status: active / draft / deprecated
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="active", index=True)
    # Дополнительные поля хранятся как JSON
    extra: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<CustomControl id={self.control_id} status={self.status}>"


# ── PolicyVersion ─────────────────────────────────────────────────────────────

class PolicyVersion(Base):
    """
    Версия политики (policy_versions.json / data/policies.json, если появится).
    Хранит конкретную версию документа политики.
    """
    __tablename__ = "policy_version"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    version: Mapped[str] = mapped_column(String(20), nullable=False, default="1.0")
    # status: draft / pending_review / approved / rejected / expired
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft", index=True)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False, default="system")
    approved_by: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    effective_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    review_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<PolicyVersion id={self.id} control={self.control_id} v={self.version}>"


# ── PolicySignature ───────────────────────────────────────────────────────────

class PolicySignature(Base):
    """
    Подпись политики (policy_signatures.json).
    Хранит конверт DocuSign/аналог с токеном подписи.
    """
    __tablename__ = "policy_signature"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    envelope_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    control_code: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    policy_title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    signer_email: Mapped[str] = mapped_column(String(200), nullable=False)
    signer_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # status: sent / signed / declined / expired
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="sent", index=True)
    signature_token: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    signed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<PolicySignature envelope={self.envelope_id} status={self.status}>"


# ── VendorRecord ──────────────────────────────────────────────────────────────

class VendorRecord(Base):
    """
    Запись вендора из vendor_inventory.json.
    Отдельная от Vendor модель — отражает структуру инвентаризации.
    """
    __tablename__ = "vendor_record"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    category: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    # data_processed: список типов данных — хранится как JSON
    data_processed: Mapped[Optional[list[str]]] = mapped_column(JSON, nullable=True)
    soc2_certified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    contract_review_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    # risk_level: critical / high / medium / low / null
    risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<VendorRecord name={self.name} soc2={self.soc2_certified}>"


# ── MDMDevice ─────────────────────────────────────────────────────────────────

class MDMDevice(Base):
    """
    Устройство из MDM-инвентаризации (mdm_device_inventory.json).
    """
    __tablename__ = "mdm_device"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(200), nullable=False)
    owner: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    os: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    # device_type: laptop / workstation / mobile / server
    device_type: Mapped[str] = mapped_column(String(50), nullable=False, default="laptop")
    filevault_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    screen_lock_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    edr_installed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    edr_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    os_up_to_date: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_check_in: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    compliant: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<MDMDevice device_id={self.device_id} owner={self.owner} compliant={self.compliant}>"


# ── HREmployee ────────────────────────────────────────────────────────────────

class HREmployee(Base):
    """
    Сотрудник из HR-реестра (hr_roster.json).
    """
    __tablename__ = "hr_employee"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    role: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    department: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    hire_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    # employment_type: full_time / part_time / contractor
    employment_type: Mapped[str] = mapped_column(String(30), nullable=False, default="full_time")
    contract_end_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    termination_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    # status: active / terminated / on_leave
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active", index=True)
    training_completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    training_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<HREmployee email={self.email} status={self.status}>"


# ── AssetRecord ───────────────────────────────────────────────────────────────

class AssetRecord(Base):
    """
    Актив из реестра активов (data/assets.json, если появится).
    Гибкая структура — дополнительные поля в JSON.
    """
    __tablename__ = "asset_record"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    # criticality: critical / high / medium / low
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    # classification: public / internal / confidential / restricted
    classification: Mapped[str] = mapped_column(String(30), nullable=False, default="internal")
    location: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="active")
    # Дополнительные поля — гибкий JSON
    extra: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<AssetRecord name={self.name} type={self.asset_type}>"


# ── AuditorComment ────────────────────────────────────────────────────────────

class AuditorComment(Base):
    """
    Комментарий аудитора к контролю (auditor_comments.json).
    """
    __tablename__ = "auditor_comment"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    control_code: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    comment: Mapped[str] = mapped_column(Text, nullable=False)
    # severity: observation / finding / exception / info
    severity: Mapped[str] = mapped_column(String(30), nullable=False, default="observation")
    auditor_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<AuditorComment control={self.control_code} severity={self.severity}>"


# ── AccessReviewDecision ──────────────────────────────────────────────────────

class AccessReviewDecision(Base):
    """
    Решение по ревью доступа пользователя (access_review_data.json).
    Ключ — user_id (u001, u002, …).
    """
    __tablename__ = "access_review_decision"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    # decision: approve / revoke / escalate
    decision: Mapped[str] = mapped_column(String(30), nullable=False)
    reviewer: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<AccessReviewDecision user={self.user_id} decision={self.decision}>"


# ── VulnerabilityRecord ───────────────────────────────────────────────────────

class VulnerabilityRecord(Base):
    """
    Запись об уязвимости (vulnerabilities.json).
    Файл содержит пустой список — модель готова к заполнению.
    """
    __tablename__ = "vulnerability_record"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # cve_id: "CVE-2024-1234" или null
    cve_id: Mapped[Optional[str]] = mapped_column(String(30), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # severity: critical / high / medium / low / info
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium", index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    affected_component: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    # status: open / in_progress / resolved / accepted / false_positive
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open", index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="manual")
    discovered_at: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<VulnerabilityRecord cve={self.cve_id} severity={self.severity} status={self.status}>"


# ── TrainingCompletionDetail ──────────────────────────────────────────────────
# Примечание: TrainingCompletion уже определён выше (legacy модель).
# TrainingCompletionDetail — расширенная версия, точно соответствующая
# структуре training_completions.json (employee_email → course_id → details).

class TrainingCompletionDetail(Base):
    """
    Детальная запись о прохождении курса (training_completions.json).
    Структура JSON: { employee_email: { course_id: { …fields… } } }.
    """
    __tablename__ = "training_completion_detail"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    employee_email: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    course_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    course_title: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    # status: passed / failed / in_progress / not_started
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="not_started")
    score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    certificate_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)
    __table_args__ = (
        UniqueConstraint("employee_email", "course_id", name="uq_training_detail_employee_course"),
    )

    def __repr__(self) -> str:
        return (
            f"<TrainingCompletionDetail employee={self.employee_email} "
            f"course={self.course_id} status={self.status}>"
        )


# ── PentestReport ─────────────────────────────────────────────────────────────

class PentestReport(Base):
    """
    Отчёт о тестировании на проникновение (pentest_reports.json).
    findings хранятся как JSON-массив объектов.
    """
    __tablename__ = "pentest_report"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # test_type: web_app / network / social_engineering / red_team / etc.
    test_type: Mapped[str] = mapped_column(String(50), nullable=False, default="web_app")
    start_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    end_date: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # findings: JSON-массив объектов { id, severity, title, description, cvss, … }
    findings: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    # status: draft / final / reviewed
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft", index=True)
    executive_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<PentestReport id={self.id} vendor={self.vendor} status={self.status}>"


# ── QuestionnaireResponse ─────────────────────────────────────────────────────

class QuestionnaireResponse(Base):
    """
    Ответ на опросник безопасности (questionnaire_responses.json).
    answers — JSON-массив объектов { question_id, question, answer, confidence, … }.
    requester — JSON-объект { company, email }.
    """
    __tablename__ = "questionnaire_response"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # questionnaire: sig_lite / caiq / custom / etc.
    questionnaire: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    questionnaire_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    # requester: { company, email }
    requester: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, nullable=True)
    total_questions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    needs_review_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # answers: JSON-массив объектов вопрос → ответ
    answers: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<QuestionnaireResponse id={self.id} questionnaire={self.questionnaire}>"


# ─── Test Engine ─────────────────────────────────────────────────────────────

class TestStatus(str, enum.Enum):
    PASS  = "PASS"
    FAIL  = "FAIL"
    ERROR = "ERROR"
    NA    = "NA"


class TestDefinition(Base):
    __tablename__ = "test_definitions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    producer: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    assertion_type: Mapped[str] = mapped_column(String(60), nullable=False)
    params: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    default_remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    frequency_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    mappings: Mapped[list["TestControlMapping"]] = relationship("TestControlMapping", back_populates="test", cascade="all, delete-orphan")
    results: Mapped[list["TestResult"]] = relationship("TestResult", back_populates="test")


class TestControlMapping(Base):
    __tablename__ = "test_control_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    test_id: Mapped[str] = mapped_column(String(36), ForeignKey("test_definitions.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id: Mapped[str] = mapped_column(String(36), ForeignKey("control.id", ondelete="CASCADE"), nullable=False, index=True)
    weight: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    __table_args__ = (UniqueConstraint("test_id", "control_id", name="uq_test_control"),)

    test: Mapped["TestDefinition"] = relationship("TestDefinition", back_populates="mappings")


class TestRun(Base):
    __tablename__ = "test_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    producer: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    trigger: Mapped[str] = mapped_column(String(30), nullable=False, default="scheduled")
    actor: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    results: Mapped[list["TestResult"]] = relationship("TestResult", back_populates="run")


class TestResult(Base):
    __tablename__ = "test_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    test_id: Mapped[str] = mapped_column(String(36), ForeignKey("test_definitions.id", ondelete="CASCADE"), nullable=False, index=True)
    run_id: Mapped[str] = mapped_column(String(36), ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, default="*")
    status: Mapped[str] = mapped_column(String(10), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    evidence_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True, default=dict)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    test: Mapped["TestDefinition"] = relationship("TestDefinition", back_populates="results")
    run: Mapped["TestRun"] = relationship("TestRun", back_populates="results")

    __table_args__ = (
        Index("ix_result_latest", "test_id", "resource_id", "evaluated_at"),
        UniqueConstraint("test_id", "resource_id", "run_id", name="uq_result_run"),
    )


# ── AuditLog ──────────────────────────────────────────────────────────────────

class AuditLog(Base):
    """
    Журнал действий пользователей («кто/что/когда»).
    Пишется при каждой мутирующей операции — отдельно от технических логов.
    Предназначен для аудиторов SOC2 (требование A11).
    Append-only: записи не изменяются и не удаляются.
    """
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user_role: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    detail: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} action={self.action} "
            f"user={self.user_email} ts={self.timestamp}>"
        )


# ── Finding ───────────────────────────────────────────────────────────────────

class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class FindingStatus(str, enum.Enum):
    OPEN           = "OPEN"
    RESOLVED       = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK  = "ACCEPTED_RISK"


class Finding(Base):
    """
    Нативная сущность Finding — создаётся автоматически при drift-переходе
    PASS→FAIL в TestResult. Живёт пока не resolved или false_positive.

    Уникальность: один открытый finding на пару (test_id, resource_id).
    Повторные FAIL обновляют last_seen_at (upsert).
    """
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    test_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("test_definitions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False, default="*")
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="OPEN", index=True
    )
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    owner_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sla_due_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    result_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("test_results.id", ondelete="SET NULL"),
        nullable=True,
    )
    detail: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    test: Mapped["TestDefinition"] = relationship("TestDefinition", lazy="selectin")

    __table_args__ = (
        UniqueConstraint("test_id", "resource_id", name="uq_finding_test_resource"),
    )

    def __repr__(self) -> str:
        return f"<Finding id={self.id} test_id={self.test_id} status={self.status}>"


# ── AiDecision ────────────────────────────────────────────────────────────────

class AiDecision(Base):
    """
    Хранит каждое AI-решение для explainability и SOC 2 audit trail.
    Заменяет хранение в data/ai_decisions.json и таблицу audit_event (event_type=ai.decision).
    """
    __tablename__ = "ai_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    agent: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    reasoning: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    outcome: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    meta: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<AiDecision id={self.id} agent={self.agent} outcome={self.outcome}>"


# ── TrustAccessRequest ────────────────────────────────────────────────────────

class TrustAccessRequest(Base):
    """
    Запрос доступа к документам Trust Center от внешнего пользователя.
    Статус: pending / approved / rejected.
    """
    __tablename__ = "trust_access_requests"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    company: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<TrustAccessRequest email={self.email} company={self.company} status={self.status}>"
