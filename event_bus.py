"""
event_bus.py — Центральная шина compliance-событий (Event Bus).

Архитектура:
  ComplianceEventType  — перечисление всех типов событий
  ComplianceEvent      — иммутабельный dataclass события
  EventBus             — singleton-шина: subscribe/publish/history

Thread-safety:
  - handlers вызываются в ThreadPoolExecutor (не блокируют publish)
  - _history защищён threading.Lock
  - subscribe/publish работают из любого потока

Graceful degradation:
  - исключение в handler журналируется, но не прерывает publish
  - запись в AuditEventRepository пропускается при недоступности БД
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from log_config import get_logger

log = get_logger(__name__)

# Максимум событий в памяти (FIFO-очередь)
_MAX_HISTORY = 1000

# Пул потоков для handlers (не блокируют event loop)
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="event-handler")


# ── Типы событий ───────────────────────────────────────────────────────────────

class ComplianceEventType(str, Enum):
    """Все типы compliance-событий в системе."""

    CONTROL_STATUS_CHANGED  = "control.status_changed"
    EVIDENCE_ADDED          = "evidence.added"
    EVIDENCE_EXPIRED        = "evidence.expired"
    RISK_CREATED            = "risk.created"
    RISK_ESCALATED          = "risk.escalated"
    VENDOR_REVIEW_DUE       = "vendor.review_due"
    POLICY_APPROVED         = "policy.approved"
    POLICY_REJECTED         = "policy.rejected"
    AUDIT_SCAN_COMPLETED    = "audit.scan_completed"
    SLA_BREACH              = "sla.breach"
    ANOMALY_DETECTED        = "anomaly.detected"


# ── Иммутабельный dataclass события ───────────────────────────────────────────

@dataclass(frozen=True)
class ComplianceEvent:
    """
    Иммутабельное compliance-событие.

    Поле severity: "info" | "warning" | "critical"
    Поле actor:    "system" | "agent:okta" | "human:admin@acme.com"
    """

    event_id:    str
    event_type:  ComplianceEventType
    entity_type: str                  # "control", "evidence", "risk", "policy", "vendor"
    entity_id:   str
    actor:       str
    payload:     Dict[str, Any]
    timestamp:   datetime
    severity:    str                  # "info" | "warning" | "critical"

    @staticmethod
    def create(
        event_type:  ComplianceEventType,
        entity_type: str,
        entity_id:   str,
        actor:       str = "system",
        payload:     Optional[Dict[str, Any]] = None,
        severity:    str = "info",
    ) -> "ComplianceEvent":
        """
        Фабричный метод: генерирует event_id и timestamp автоматически.

        Использование:
          event = ComplianceEvent.create(
              event_type=ComplianceEventType.EVIDENCE_ADDED,
              entity_type="evidence",
              entity_id=ev_id,
              actor="agent:okta",
              payload={"control_id": "CC6.1"},
              severity="info",
          )
        """
        return ComplianceEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            actor=actor,
            payload=dict(payload or {}),
            timestamp=datetime.now(timezone.utc),
            severity=severity,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует событие в словарь для API / сериализации."""
        return {
            "event_id":    self.event_id,
            "event_type":  self.event_type.value,
            "entity_type": self.entity_type,
            "entity_id":   self.entity_id,
            "actor":       self.actor,
            "payload":     self.payload,
            "timestamp":   self.timestamp.isoformat(),
            "severity":    self.severity,
        }


# Тип обработчика события
HandlerFn = Callable[[ComplianceEvent], None]


# ── EventBus — центральная шина ────────────────────────────────────────────────

class EventBus:
    """
    Singleton-шина compliance-событий.

    Жизненный цикл:
      1. Handlers регистрируются через subscribe()
      2. Компоненты публикуют события через publish() или publish_async()
      3. EventBus вызывает все handlers в thread pool (non-blocking)
      4. Каждое событие записывается в AuditEventRepository (если DB доступна)
      5. История событий доступна через get_history()

    Thread-safety: все операции защищены threading.Lock.
    """

    def __init__(self) -> None:
        # Реестр обработчиков: event_type → список функций
        self._handlers: Dict[ComplianceEventType, List[HandlerFn]] = {}
        # История событий в памяти (FIFO)
        self._history: deque[ComplianceEvent] = deque(maxlen=_MAX_HISTORY)
        # Мьютекс для thread-safe доступа
        self._lock = threading.Lock()
        # Регистрируем встроенные обработчики
        self._register_builtin_handlers()

    # ── Регистрация ────────────────────────────────────────────────────────────

    def subscribe(
        self,
        event_type: ComplianceEventType,
        handler_fn: HandlerFn,
    ) -> None:
        """
        Регистрирует обработчик для указанного типа события.

        Один event_type может иметь несколько handlers.
        Порядок вызова — порядок регистрации.
        """
        with self._lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            self._handlers[event_type].append(handler_fn)
            log.info(
                "EventBus: зарегистрирован handler",
                extra={"event_type": event_type.value, "handler": handler_fn.__qualname__},
            )

    def subscribe_all(self, handler_fn: HandlerFn) -> None:
        """Регистрирует обработчик для ВСЕХ типов событий."""
        for event_type in ComplianceEventType:
            self.subscribe(event_type, handler_fn)

    # ── Публикация (синхронная) ────────────────────────────────────────────────

    def publish(self, event: ComplianceEvent) -> None:
        """
        Публикует событие:
          1. Добавляет в историю
          2. Записывает в AuditEventRepository (graceful fail)
          3. Запускает все handlers в thread pool (non-blocking)

        Не блокирует: handlers выполняются асинхронно в ThreadPoolExecutor.
        Исключение в handler журналируется, но не прерывает publish.
        """
        # Добавляем в историю (thread-safe)
        with self._lock:
            self._history.append(event)
            handlers = list(self._handlers.get(event.event_type, []))

        log.info(
            "EventBus: публикуется событие",
            extra={
                "event_id":   event.event_id,
                "event_type": event.event_type.value,
                "entity_id":  event.entity_id,
                "severity":   event.severity,
                "handlers":   len(handlers),
            },
        )

        # Запись в AuditEventRepository (non-blocking, best-effort)
        _EXECUTOR.submit(self._persist_to_db, event)

        # Вызываем все handlers в thread pool
        for handler_fn in handlers:
            _EXECUTOR.submit(self._safe_call_handler, handler_fn, event)

    async def publish_async(self, event: ComplianceEvent) -> None:
        """
        Async-версия publish для использования в async-контексте.

        Запускает publish в executor чтобы не блокировать event loop.
        Handlers всё равно вызываются асинхронно в thread pool.

        Использование:
          await event_bus.publish_async(event)
        """
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(_EXECUTOR, self.publish, event)

    # ── История событий ────────────────────────────────────────────────────────

    def get_history(
        self,
        entity_id:  Optional[str] = None,
        event_type: Optional[ComplianceEventType] = None,
        severity:   Optional[str] = None,
        limit:      int = 50,
    ) -> List[ComplianceEvent]:
        """
        Возвращает историю событий из памяти (от новых к старым).

        Фильтры:
          entity_id  — только события для этой сущности
          event_type — только события данного типа
          severity   — только события данного уровня
          limit      — максимальное количество событий
        """
        with self._lock:
            # Копируем в обратном порядке (новые первые)
            events = list(reversed(self._history))

        if entity_id:
            events = [e for e in events if e.entity_id == entity_id]
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if severity:
            events = [e for e in events if e.severity == severity]

        return events[:limit]

    def get_stats(self, since: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Статистика по событиям в памяти.

        Возвращает:
          total       — общее количество
          by_type     — счётчики по типам
          by_severity — счётчики по уровням
        """
        with self._lock:
            events = list(self._history)

        if since:
            events = [e for e in events if e.timestamp >= since]

        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}

        for event in events:
            by_type[event.event_type.value] = by_type.get(event.event_type.value, 0) + 1
            by_severity[event.severity]     = by_severity.get(event.severity, 0) + 1

        return {
            "total":       len(events),
            "by_type":     by_type,
            "by_severity": by_severity,
        }

    def clear_history(self) -> None:
        """Очищает историю событий в памяти (для тестов)."""
        with self._lock:
            self._history.clear()

    def unsubscribe_all(self) -> None:
        """Снимает все handlers (для тестов — изоляция)."""
        with self._lock:
            self._handlers.clear()
            # Сразу регистрируем встроенные handlers под той же блокировкой
            self._handlers[ComplianceEventType.EVIDENCE_ADDED] = [self._handle_sla_check]

    # ── Встроенные handlers ────────────────────────────────────────────────────

    def _register_builtin_handlers(self) -> None:
        """Регистрирует встроенные handlers под lock."""
        with self._lock:
            if ComplianceEventType.EVIDENCE_ADDED not in self._handlers:
                self._handlers[ComplianceEventType.EVIDENCE_ADDED] = []
            if self._handle_sla_check not in self._handlers[ComplianceEventType.EVIDENCE_ADDED]:
                self._handlers[ComplianceEventType.EVIDENCE_ADDED].append(self._handle_sla_check)

    def _handle_sla_check(self, event: ComplianceEvent) -> None:
        """
        Встроенный handler: при добавлении evidence проверяет freshness.

        Если evidence старше SLA (часы из ontology или 720ч по умолчанию),
        публикует дочернее событие SLA_BREACH.
        """
        try:
            payload = event.payload
            control_id = payload.get("control_id", "")
            created_at_raw = payload.get("created_at")

            if not created_at_raw:
                return

            # Определяем SLA для контроля (из ontology или дефолт 720ч = 30 дней)
            sla_hours = self._get_sla_hours(control_id)

            # Парсим дату создания evidence
            if isinstance(created_at_raw, str):
                try:
                    created_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
                except ValueError:
                    return
            elif isinstance(created_at_raw, datetime):
                created_at = created_at_raw
            else:
                return

            # Добавляем timezone если отсутствует
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_hours = (now - created_at).total_seconds() / 3600

            if age_hours > sla_hours:
                breach_event = ComplianceEvent.create(
                    event_type=ComplianceEventType.SLA_BREACH,
                    entity_type="evidence",
                    entity_id=event.entity_id,
                    actor="system:sla_checker",
                    payload={
                        "control_id":   control_id,
                        "evidence_id":  event.entity_id,
                        "age_hours":    round(age_hours, 1),
                        "sla_hours":    sla_hours,
                        "source_event": event.event_id,
                    },
                    severity="warning",
                )
                log.warning(
                    "EventBus: SLA breach обнаружен",
                    extra={
                        "evidence_id": event.entity_id,
                        "control_id":  control_id,
                        "age_hours":   age_hours,
                        "sla_hours":   sla_hours,
                    },
                )
                # Публикуем SLA_BREACH — НЕ через publish() чтобы избежать рекурсии
                self._publish_internal(breach_event)

        except Exception as exc:
            log.error(
                "EventBus: ошибка в _handle_sla_check",
                extra={"error": str(exc), "event_id": event.event_id},
            )

    def _get_sla_hours(self, control_id: str) -> float:
        """
        Возвращает SLA в часах для контроля из онтологии.
        По умолчанию 720 часов (30 дней).
        """
        if not control_id:
            return 720.0
        try:
            from compliance_ontology import get_ontology_engine
            engine = get_ontology_engine()
            ctrl = engine.get_control(control_id)
            if ctrl and hasattr(ctrl, "sla_hours") and ctrl.sla_hours:
                return float(ctrl.sla_hours)
        except Exception:
            pass
        return 720.0

    # ── Внутренние хелперы ─────────────────────────────────────────────────────

    def _publish_internal(self, event: ComplianceEvent) -> None:
        """
        Внутренняя публикация (без повторного вызова _handle_sla_check).
        Добавляет в историю и вызывает handlers кроме встроенных.
        """
        with self._lock:
            self._history.append(event)
            handlers = [
                h for h in self._handlers.get(event.event_type, [])
                if h is not self._handle_sla_check  # избегаем рекурсии
            ]

        _EXECUTOR.submit(self._persist_to_db, event)
        for handler_fn in handlers:
            _EXECUTOR.submit(self._safe_call_handler, handler_fn, event)

    def _safe_call_handler(
        self,
        handler_fn: HandlerFn,
        event: ComplianceEvent,
    ) -> None:
        """
        Вызывает handler с перехватом исключений.
        Исключение не прерывает обработку других handlers.
        """
        try:
            handler_fn(event)
        except Exception as exc:
            log.error(
                "EventBus: исключение в handler",
                extra={
                    "handler":    handler_fn.__qualname__,
                    "event_type": event.event_type.value,
                    "event_id":   event.event_id,
                    "error":      str(exc),
                },
            )

    def _persist_to_db(self, event: ComplianceEvent) -> None:
        """
        Записывает событие в AuditEventRepository и EventQueue (best-effort).

        AuditEvent — immutable audit trail (существующая логика).
        EventQueue  — durable очередь для cross-process доставки: агенты в
                      subprocess/Celery пишут сюда, веб-процесс читает и
                      вызывает in-memory handlers через polling-воркер.

        Не поднимает исключений — только журналирует ошибки.
        """
        try:
            import json as _json
            from database import AsyncSessionLocal
            from db_repository import AuditEventRepository, EventQueueRepository

            async def _do_persist() -> None:
                async with AsyncSessionLocal() as session:
                    # 1. AuditEvent — immutable audit trail
                    audit_repo = AuditEventRepository(session)
                    await audit_repo.append(
                        event_type=event.event_type.value,
                        entity_type=event.entity_type,
                        entity_id=event.entity_id,
                        actor=event.actor,
                        payload={
                            **event.payload,
                            "event_id": event.event_id,
                            "severity": event.severity,
                        },
                    )

                    # 2. EventQueue — durable cross-process delivery
                    queue_repo = EventQueueRepository(session)
                    full_payload = _json.dumps(event.to_dict(), ensure_ascii=False)
                    await queue_repo.enqueue(
                        event_id=event.event_id,
                        event_type=event.event_type.value,
                        entity_id=event.entity_id,
                        payload=full_payload,
                    )

                    await session.commit()

            # Запускаем в новом event loop (мы уже в thread pool)
            asyncio.run(_do_persist())

        except Exception as exc:
            # DB недоступна — это нормально для dev-режима
            log.debug(
                "EventBus: не удалось сохранить событие в БД (dev-режим?)",
                extra={"event_id": event.event_id, "error": str(exc)},
            )


# ── Singleton ──────────────────────────────────────────────────────────────────

_event_bus_instance: Optional[EventBus] = None
_singleton_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """
    Thread-safe singleton EventBus.

    Гарантирует единственный экземпляр даже при конкурентном создании.
    Использование: bus = get_event_bus()
    """
    global _event_bus_instance
    if _event_bus_instance is None:
        with _singleton_lock:
            if _event_bus_instance is None:
                _event_bus_instance = EventBus()
                log.info("EventBus: singleton создан")
    return _event_bus_instance
