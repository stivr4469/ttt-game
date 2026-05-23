"""
event_handlers.py — Стандартные обработчики compliance-событий.

Handlers:
  AuditTrailHandler     — каждое событие → AuditEventRepository
  SlackEventHandler     — CRITICAL события → Slack уведомление
  RiskEscalationHandler — CONTROL_STATUS_CHANGED(FAIL) → создаёт RiskEntry
  SLABreachHandler      — SLA_BREACH → запись в ai_decision_log

Все handlers gracefully fail: исключение журналируется, не пробрасывается.
Все handlers регистрируются при импорте модуля через setup_default_handlers().

Использование:
  from event_handlers import setup_default_handlers
  setup_default_handlers()  # регистрирует все handlers в EventBus singleton
"""

from __future__ import annotations

import os
from typing import Optional

from event_bus import ComplianceEvent, ComplianceEventType, EventBus, get_event_bus
from log_config import get_logger

log = get_logger(__name__)


# ── AuditTrailHandler ──────────────────────────────────────────────────────────

class AuditTrailHandler:
    """
    Записывает КАЖДОЕ событие в AuditEventRepository.

    Дублирует _persist_to_db в EventBus? Нет: EventBus пишет в DB async,
    этот handler пишет структурированный аудит-трейл синхронно в thread pool.
    Используется как надёжный fallback при отключённой DB.
    """

    def __call__(self, event: ComplianceEvent) -> None:
        """Записывает событие в audit trail."""
        try:
            import asyncio
            from database import AsyncSessionLocal
            from db_repository import AuditEventRepository

            async def _persist() -> None:
                async with AsyncSessionLocal() as session:
                    repo = AuditEventRepository(session)
                    await repo.append(
                        event_type=f"bus.{event.event_type.value}",
                        entity_type=event.entity_type,
                        entity_id=event.entity_id,
                        actor=event.actor,
                        payload={
                            "event_id":   event.event_id,
                            "severity":   event.severity,
                            "bus_payload": event.payload,
                        },
                    )
                    await session.commit()

            asyncio.run(_persist())

        except Exception as exc:
            # В dev-режиме без DB — тихий fail
            log.debug(
                "AuditTrailHandler: пропущена запись в DB",
                extra={"event_id": event.event_id, "error": str(exc)},
            )


# ── SlackEventHandler ──────────────────────────────────────────────────────────

class SlackEventHandler:
    """
    Отправляет Slack-уведомление при CRITICAL событиях.

    Настройка: SLACK_WEBHOOK_URL в переменных окружения.
    Если webhook не настроен — handler тихо пропускает.
    """

    def __call__(self, event: ComplianceEvent) -> None:
        """Уведомляет в Slack только если severity == "critical"."""
        if event.severity != "critical":
            return

        webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        if not webhook_url:
            log.debug("SlackEventHandler: SLACK_WEBHOOK_URL не задан, пропускаем")
            return

        try:
            from slack_notifier import SlackNotifier
            notifier = SlackNotifier(webhook_url)

            # Формируем violation-подобный payload для send_violation
            violation = {
                "control_code": event.payload.get("control_id", event.entity_id),
                "severity":     "CRITICAL",
                "source":       f"event_bus:{event.event_type.value}",
                "finding": (
                    f"[{event.event_type.value}] "
                    f"entity={event.entity_type}/{event.entity_id} "
                    f"actor={event.actor}"
                ),
            }
            success = notifier.send_violation(violation)
            log.info(
                "SlackEventHandler: уведомление отправлено",
                extra={
                    "event_id":   event.event_id,
                    "event_type": event.event_type.value,
                    "success":    success,
                },
            )
        except Exception as exc:
            log.error(
                "SlackEventHandler: ошибка отправки в Slack",
                extra={"event_id": event.event_id, "error": str(exc)},
            )


# ── RiskEscalationHandler ──────────────────────────────────────────────────────

class RiskEscalationHandler:
    """
    При CONTROL_STATUS_CHANGED → FAIL создаёт автоматическую запись в risk register.

    Логика:
      1. Проверяем что новый статус == "FAIL"
      2. Проверяем что риска с этим control_id ещё нет (open)
      3. Создаём RiskEntry со score = likelihood * impact (5 * 4 = 20 по умолчанию)
    """

    def __call__(self, event: ComplianceEvent) -> None:
        """Создаёт риск при FAIL-статусе контроля."""
        if event.event_type != ComplianceEventType.CONTROL_STATUS_CHANGED:
            return

        payload = event.payload
        new_status = payload.get("new_status", payload.get("status", "")).upper()

        if new_status != "FAIL":
            return

        control_id = payload.get("control_id", event.entity_id)

        try:
            from risk_register import RiskRegister
            register = RiskRegister()

            # Проверяем — нет ли уже открытого риска для этого контроля
            existing = register.get_all(status="open")
            for risk in existing:
                if risk.get("control_id") == control_id:
                    log.info(
                        "RiskEscalationHandler: риск для контроля уже существует, пропускаем",
                        extra={"control_id": control_id, "risk_id": risk.get("id")},
                    )
                    return

            # Создаём новый риск
            risk_data = {
                "title":          f"Автоматический риск: контрол {control_id} в статусе FAIL",
                "description":    (
                    f"Контрол {control_id} перешёл в статус FAIL. "
                    f"Событие: {event.event_id}. Актор: {event.actor}."
                ),
                "control_id":     control_id,
                "source":         "event_bus",
                "likelihood":     4,   # высокая вероятность (1-5)
                "impact":         5,   # критический импакт
                "category":       "operational",
                "owner":          "security-team",
                "treatment":      "mitigate",
                "treatment_plan": f"Исправить контрол {control_id}. Добавить недостающие evidence.",
                "status":         "open",
            }
            created = register.create(risk_data)

            # Публикуем RISK_ESCALATED чтобы другие handlers знали
            bus = get_event_bus()
            from event_bus import ComplianceEvent
            escalation = ComplianceEvent.create(
                event_type=ComplianceEventType.RISK_ESCALATED,
                entity_type="risk",
                entity_id=created.get("id", "unknown"),
                actor="system:risk_escalation",
                payload={
                    "control_id":     control_id,
                    "source_event":   event.event_id,
                    "risk_id":        created.get("id"),
                    "risk_score":     created.get("score"),
                },
                severity="warning",
            )
            bus._publish_internal(escalation)

            log.info(
                "RiskEscalationHandler: создан риск для контроля",
                extra={
                    "control_id": control_id,
                    "risk_id":    created.get("id"),
                    "event_id":   event.event_id,
                },
            )

        except Exception as exc:
            log.error(
                "RiskEscalationHandler: ошибка создания риска",
                extra={
                    "control_id": control_id,
                    "event_id":   event.event_id,
                    "error":      str(exc),
                },
            )


# ── SLABreachHandler ──────────────────────────────────────────────────────────

class SLABreachHandler:
    """
    При SLA_BREACH записывает CRITICAL решение в ai_decision_log.

    Это нужно для audit trail: аудитор должен видеть что SLA было нарушено.
    """

    def __call__(self, event: ComplianceEvent) -> None:
        """Логирует SLA breach в ai_decision_log."""
        if event.event_type != ComplianceEventType.SLA_BREACH:
            return

        try:
            from ai_decision_log import get_decision_logger, DecisionType

            payload = event.payload
            control_id = payload.get("control_id", "")
            age_hours = payload.get("age_hours", 0)
            sla_hours = payload.get("sla_hours", 720)
            evidence_id = payload.get("evidence_id", event.entity_id)

            logger = get_decision_logger()
            logger.record(
                decision_type=DecisionType.CONTROL_ASSESSMENT,
                model="system:event_bus",
                prompt=(
                    f"SLA проверка evidence {evidence_id} для контроля {control_id}. "
                    f"SLA = {sla_hours}ч."
                ),
                output=(
                    f"CRITICAL: evidence {evidence_id} просрочено на "
                    f"{age_hours - sla_hours:.1f}ч (возраст {age_hours}ч, SLA {sla_hours}ч). "
                    f"Требуется обновление evidence для контроля {control_id}."
                ),
                outcome="SLA_BREACH",
                control_id=control_id or None,
                evidence_used=[evidence_id],
                duration_ms=0,
                metadata={
                    "event_id":    event.event_id,
                    "age_hours":   age_hours,
                    "sla_hours":   sla_hours,
                    "severity":    "CRITICAL",
                    "breach_type": "evidence_freshness",
                },
            )
            log.warning(
                "SLABreachHandler: SLA breach записан в ai_decision_log",
                extra={
                    "evidence_id": evidence_id,
                    "control_id":  control_id,
                    "age_hours":   age_hours,
                    "sla_hours":   sla_hours,
                },
            )

        except Exception as exc:
            log.error(
                "SLABreachHandler: ошибка записи в ai_decision_log",
                extra={"event_id": event.event_id, "error": str(exc)},
            )


# ── Инициализация: регистрация всех handlers ──────────────────────────────────

_handlers_registered = False
_handlers_lock = __import__("threading").Lock()


def setup_default_handlers(bus: Optional[EventBus] = None) -> None:
    """
    Регистрирует все стандартные handlers в EventBus.

    Идемпотентна: повторный вызов не дублирует handlers.
    Вызывается автоматически при первом импорте модуля.

    Args:
        bus: экземпляр EventBus. По умолчанию — singleton get_event_bus().
    """
    global _handlers_registered

    with _handlers_lock:
        if _handlers_registered:
            return
        _handlers_registered = True

    if bus is None:
        bus = get_event_bus()

    audit_handler     = AuditTrailHandler()
    slack_handler     = SlackEventHandler()
    risk_handler      = RiskEscalationHandler()
    sla_breach_handler = SLABreachHandler()

    # AuditTrailHandler — на все события
    bus.subscribe_all(audit_handler)

    # SlackEventHandler — на все события (фильтрует внутри по severity)
    bus.subscribe_all(slack_handler)

    # RiskEscalationHandler — только на смену статуса контрола
    bus.subscribe(ComplianceEventType.CONTROL_STATUS_CHANGED, risk_handler)

    # SLABreachHandler — только на SLA-нарушения
    bus.subscribe(ComplianceEventType.SLA_BREACH, sla_breach_handler)

    log.info("EventBus: стандартные handlers зарегистрированы")


# Автоматическая регистрация при первом импорте
# Можно отключить: EVENT_BUS_NO_AUTO_SETUP=1
if not os.getenv("EVENT_BUS_NO_AUTO_SETUP"):
    try:
        setup_default_handlers()
    except Exception as _setup_exc:
        log.error("event_handlers: автоматическая setup_default_handlers() не удалась", extra={"error": str(_setup_exc)})
