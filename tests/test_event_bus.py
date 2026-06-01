"""
Тесты Compliance Event Bus — event_bus.py и event_handlers.py.

Покрывают:
  1.  ComplianceEvent.create() — корректное создание события
  2.  EventBus.subscribe() — регистрация handler
  3.  EventBus.publish() — вызов зарегистрированных handlers
  4.  EventBus — graceful fail при исключении в handler
  5.  EventBus.get_history() — история событий
  6.  EventBus.get_history(entity_id) — фильтрация по entity_id
  7.  EventBus.get_history(event_type) — фильтрация по типу
  8.  EventBus.get_history(severity) — фильтрация по уровню
  9.  EventBus.get_history(limit) — ограничение количества
  10. EventBus.get_stats() — общая статистика
  11. EventBus.get_stats(since) — статистика за период
  12. EventBus._handle_sla_check() — fresh evidence не нарушает SLA
  13. EventBus._handle_sla_check() — просроченное evidence публикует SLA_BREACH
  14. EventBus.publish_async() — async публикация
  15. EventBus.subscribe_all() — подписка на все типы
  16. SlackEventHandler — не отправляет без webhook
  17. SlackEventHandler — не отправляет при severity != "critical"
  18. RiskEscalationHandler — не создаёт риск при статусе PASS
  19. RiskEscalationHandler — создаёт риск при статусе FAIL
  20. SLABreachHandler — логирует SLA breach в ai_decision_log
  21. EventBus — множество подписчиков на один тип
  22. ComplianceEvent.to_dict() — корректная сериализация
  23. get_event_bus() — singleton поведение
  24. EventBus — FIFO история при переполнении
  25. EventBus — thread-safety при параллельной публикации
"""

from __future__ import annotations

import asyncio
import sys
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import List
from unittest.mock import MagicMock, patch

import pytest

# Добавляем корень проекта в path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Изолируем EventBus от автоматической регистрации handlers
os.environ.setdefault("EVENT_BUS_NO_AUTO_SETUP", "1")

from event_bus import (
    ComplianceEvent,
    ComplianceEventType,
    EventBus,
    get_event_bus,
    _event_bus_instance,
)


# ── Фикстуры ──────────────────────────────────────────────────────────────────

@pytest.fixture
def fresh_bus() -> EventBus:
    """Создаёт изолированный EventBus для каждого теста."""
    bus = EventBus()
    # Очищаем встроенные handlers для изоляции (переустановим только нужные)
    bus.unsubscribe_all()
    return bus


@pytest.fixture
def sample_event() -> ComplianceEvent:
    """Базовое тестовое событие."""
    return ComplianceEvent.create(
        event_type=ComplianceEventType.EVIDENCE_ADDED,
        entity_type="evidence",
        entity_id="ev-001",
        actor="test",
        payload={"control_id": "CC6.1"},
        severity="info",
    )


@pytest.fixture
def control_fail_event() -> ComplianceEvent:
    """Событие о смене статуса контрола на FAIL."""
    return ComplianceEvent.create(
        event_type=ComplianceEventType.CONTROL_STATUS_CHANGED,
        entity_type="control",
        entity_id="CC6.1",
        actor="system",
        payload={
            "control_id":  "CC6.1",
            "new_status":  "FAIL",
            "previous_status": "PASS",
        },
        severity="critical",
    )


@pytest.fixture
def sla_breach_event() -> ComplianceEvent:
    """Событие о нарушении SLA."""
    return ComplianceEvent.create(
        event_type=ComplianceEventType.SLA_BREACH,
        entity_type="evidence",
        entity_id="ev-999",
        actor="system:sla_checker",
        payload={
            "control_id":  "CC7.4",
            "evidence_id": "ev-999",
            "age_hours":   800.0,
            "sla_hours":   720.0,
        },
        severity="warning",
    )


# ── Тест 1: ComplianceEvent.create() ──────────────────────────────────────────

def test_compliance_event_create_fills_fields():
    """ComplianceEvent.create() должен заполнять event_id и timestamp."""
    event = ComplianceEvent.create(
        event_type=ComplianceEventType.RISK_CREATED,
        entity_type="risk",
        entity_id="RISK-001",
        actor="agent:okta",
        payload={"control_id": "CC3.2"},
        severity="warning",
    )
    assert event.event_id, "event_id должен быть сгенерирован"
    assert event.timestamp, "timestamp должен быть установлен"
    assert event.event_type == ComplianceEventType.RISK_CREATED
    assert event.entity_id == "RISK-001"
    assert event.severity == "warning"
    assert event.payload == {"control_id": "CC3.2"}


# ── Тест 2: EventBus.subscribe() ──────────────────────────────────────────────

def test_subscribe_registers_handler(fresh_bus: EventBus):
    """subscribe() должен добавить handler в реестр."""
    calls: List[ComplianceEvent] = []

    def handler(e: ComplianceEvent) -> None:
        calls.append(e)

    fresh_bus.subscribe(ComplianceEventType.RISK_CREATED, handler)

    # Проверяем что handler зарегистрирован
    with fresh_bus._lock:
        handlers = fresh_bus._handlers.get(ComplianceEventType.RISK_CREATED, [])
    assert handler in handlers


# ── Тест 3: EventBus.publish() вызывает handler ───────────────────────────────

def test_publish_calls_handler(fresh_bus: EventBus, sample_event: ComplianceEvent):
    """publish() должен вызвать зарегистрированный handler."""
    calls: List[ComplianceEvent] = []
    done = threading.Event()

    def handler(e: ComplianceEvent) -> None:
        calls.append(e)
        done.set()

    fresh_bus.subscribe(ComplianceEventType.EVIDENCE_ADDED, handler)
    fresh_bus.publish(sample_event)

    # Ожидаем вызова handler (он в thread pool)
    done.wait(timeout=3.0)
    assert len(calls) == 1
    assert calls[0].event_id == sample_event.event_id


# ── Тест 4: Graceful fail при исключении в handler ────────────────────────────

def test_publish_graceful_fail_in_handler(fresh_bus: EventBus, sample_event: ComplianceEvent):
    """Исключение в handler не должно прерывать publish и не должно подниматься."""
    second_call = threading.Event()
    calls: List[str] = []

    def failing_handler(e: ComplianceEvent) -> None:
        raise RuntimeError("Тестовая ошибка handler")

    def good_handler(e: ComplianceEvent) -> None:
        calls.append(e.event_id)
        second_call.set()

    fresh_bus.subscribe(ComplianceEventType.EVIDENCE_ADDED, failing_handler)
    fresh_bus.subscribe(ComplianceEventType.EVIDENCE_ADDED, good_handler)

    # Publish не должен поднимать исключение
    fresh_bus.publish(sample_event)
    second_call.wait(timeout=3.0)

    # Второй (корректный) handler должен был быть вызван
    assert sample_event.event_id in calls


# ── Тест 5: EventBus.get_history() ───────────────────────────────────────────

def test_get_history_returns_published_events(fresh_bus: EventBus):
    """get_history() должен вернуть опубликованные события."""
    ev1 = ComplianceEvent.create(
        event_type=ComplianceEventType.POLICY_APPROVED,
        entity_type="policy",
        entity_id="POL-001",
    )
    ev2 = ComplianceEvent.create(
        event_type=ComplianceEventType.RISK_CREATED,
        entity_type="risk",
        entity_id="RISK-001",
    )
    fresh_bus.publish(ev1)
    fresh_bus.publish(ev2)

    history = fresh_bus.get_history(limit=10)
    ids = [e.event_id for e in history]
    assert ev1.event_id in ids
    assert ev2.event_id in ids


# ── Тест 6: Фильтрация по entity_id ──────────────────────────────────────────

def test_get_history_filter_by_entity_id(fresh_bus: EventBus):
    """get_history(entity_id=) должен вернуть только события нужной сущности."""
    ev_target = ComplianceEvent.create(
        event_type=ComplianceEventType.EVIDENCE_ADDED,
        entity_type="evidence",
        entity_id="ev-TARGET",
    )
    ev_other = ComplianceEvent.create(
        event_type=ComplianceEventType.EVIDENCE_ADDED,
        entity_type="evidence",
        entity_id="ev-OTHER",
    )
    fresh_bus.publish(ev_target)
    fresh_bus.publish(ev_other)

    result = fresh_bus.get_history(entity_id="ev-TARGET")
    assert all(e.entity_id == "ev-TARGET" for e in result)
    assert any(e.event_id == ev_target.event_id for e in result)


# ── Тест 7: Фильтрация по event_type ─────────────────────────────────────────

def test_get_history_filter_by_event_type(fresh_bus: EventBus):
    """get_history(event_type=) должен вернуть только события нужного типа."""
    ev_evidence = ComplianceEvent.create(
        event_type=ComplianceEventType.EVIDENCE_ADDED,
        entity_type="evidence",
        entity_id="ev-001",
    )
    ev_risk = ComplianceEvent.create(
        event_type=ComplianceEventType.RISK_CREATED,
        entity_type="risk",
        entity_id="RISK-001",
    )
    fresh_bus.publish(ev_evidence)
    fresh_bus.publish(ev_risk)

    result = fresh_bus.get_history(event_type=ComplianceEventType.EVIDENCE_ADDED)
    assert all(e.event_type == ComplianceEventType.EVIDENCE_ADDED for e in result)


# ── Тест 8: Фильтрация по severity ───────────────────────────────────────────

def test_get_history_filter_by_severity(fresh_bus: EventBus):
    """get_history(severity=) должен вернуть только события нужного уровня."""
    ev_info = ComplianceEvent.create(
        event_type=ComplianceEventType.POLICY_APPROVED,
        entity_type="policy",
        entity_id="POL-001",
        severity="info",
    )
    ev_critical = ComplianceEvent.create(
        event_type=ComplianceEventType.SLA_BREACH,
        entity_type="evidence",
        entity_id="ev-001",
        severity="critical",
    )
    fresh_bus.publish(ev_info)
    fresh_bus.publish(ev_critical)

    result = fresh_bus.get_history(severity="critical")
    assert all(e.severity == "critical" for e in result)
    assert any(e.event_id == ev_critical.event_id for e in result)


# ── Тест 9: Лимит в get_history ───────────────────────────────────────────────

def test_get_history_limit(fresh_bus: EventBus):
    """get_history(limit=N) должен вернуть не более N событий."""
    for i in range(20):
        ev = ComplianceEvent.create(
            event_type=ComplianceEventType.AUDIT_SCAN_COMPLETED,
            entity_type="scan",
            entity_id=f"scan-{i}",
        )
        fresh_bus.publish(ev)

    result = fresh_bus.get_history(limit=5)
    assert len(result) <= 5


# ── Тест 10: EventBus.get_stats() ────────────────────────────────────────────

def test_get_stats_counts_events(fresh_bus: EventBus):
    """get_stats() должен корректно подсчитывать события по типам."""
    for _ in range(3):
        fresh_bus.publish(ComplianceEvent.create(
            event_type=ComplianceEventType.EVIDENCE_ADDED,
            entity_type="evidence",
            entity_id="ev-x",
            severity="info",
        ))
    for _ in range(2):
        fresh_bus.publish(ComplianceEvent.create(
            event_type=ComplianceEventType.RISK_CREATED,
            entity_type="risk",
            entity_id="RISK-x",
            severity="warning",
        ))

    stats = fresh_bus.get_stats()
    assert stats["total"] >= 5
    assert stats["by_type"].get(ComplianceEventType.EVIDENCE_ADDED.value, 0) >= 3
    assert stats["by_type"].get(ComplianceEventType.RISK_CREATED.value, 0) >= 2


# ── Тест 11: get_stats(since) — фильтрация по времени ────────────────────────

def test_get_stats_since_filters_by_time(fresh_bus: EventBus):
    """get_stats(since=) должен считать только события после указанного времени."""
    # Публикуем событие
    fresh_bus.publish(ComplianceEvent.create(
        event_type=ComplianceEventType.POLICY_APPROVED,
        entity_type="policy",
        entity_id="POL-001",
        severity="info",
    ))

    # Устанавливаем since на будущее — должны получить 0 событий
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    stats = fresh_bus.get_stats(since=future)
    assert stats["total"] == 0


# ── Тест 12: _handle_sla_check — свежее evidence ─────────────────────────────

def test_sla_check_fresh_evidence_no_breach(fresh_bus: EventBus):
    """Свежее evidence (возраст < SLA) не должно публиковать SLA_BREACH."""
    sla_breach_calls: List[ComplianceEvent] = []

    def capture_sla_breach(e: ComplianceEvent) -> None:
        if e.event_type == ComplianceEventType.SLA_BREACH:
            sla_breach_calls.append(e)

    fresh_bus.subscribe(ComplianceEventType.SLA_BREACH, capture_sla_breach)

    # Свежее evidence — только что создано
    ev = ComplianceEvent.create(
        event_type=ComplianceEventType.EVIDENCE_ADDED,
        entity_type="evidence",
        entity_id="ev-fresh",
        payload={
            "control_id": "CC6.1",
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
        severity="info",
    )

    # Вызываем built-in handler напрямую
    fresh_bus._handle_sla_check(ev)
    time.sleep(0.1)  # небольшая пауза для thread pool

    assert len(sla_breach_calls) == 0, "Свежее evidence не должно нарушать SLA"


# ── Тест 13: _handle_sla_check — просроченное evidence ───────────────────────

def test_sla_check_expired_evidence_triggers_breach(fresh_bus: EventBus):
    """Просроченное evidence (возраст > SLA) должно публиковать SLA_BREACH."""
    breach_received = threading.Event()
    breach_events: List[ComplianceEvent] = []

    def capture_sla_breach(e: ComplianceEvent) -> None:
        breach_events.append(e)
        breach_received.set()

    fresh_bus.subscribe(ComplianceEventType.SLA_BREACH, capture_sla_breach)

    # Просроченное evidence — создано 800 часов назад (SLA = 720ч)
    old_date = datetime.now(timezone.utc) - timedelta(hours=800)
    ev = ComplianceEvent.create(
        event_type=ComplianceEventType.EVIDENCE_ADDED,
        entity_type="evidence",
        entity_id="ev-old",
        payload={
            "control_id": "CC7.4",
            "created_at": old_date.isoformat(),
        },
        severity="info",
    )

    # Мокируем get_ontology_engine чтобы вернуть SLA = 720ч
    with patch("event_bus.EventBus._get_sla_hours", return_value=720.0):
        fresh_bus._handle_sla_check(ev)

    breach_received.wait(timeout=3.0)

    assert len(breach_events) >= 1, "SLA_BREACH должно быть опубликовано"
    breach = breach_events[0]
    assert breach.event_type == ComplianceEventType.SLA_BREACH
    assert breach.payload.get("age_hours", 0) > 720


# ── Тест 14: EventBus.publish_async() ────────────────────────────────────────

@pytest.mark.asyncio
async def test_publish_async_delivers_event(fresh_bus: EventBus):
    """publish_async() должен асинхронно доставить событие."""
    received = asyncio.Event()
    calls: List[ComplianceEvent] = []

    def handler(e: ComplianceEvent) -> None:
        calls.append(e)
        # Сигнализируем через threading.Event (т.к. handler в другом потоке)
        done_flag.set()

    done_flag = threading.Event()
    fresh_bus.subscribe(ComplianceEventType.ANOMALY_DETECTED, handler)

    ev = ComplianceEvent.create(
        event_type=ComplianceEventType.ANOMALY_DETECTED,
        entity_type="scan",
        entity_id="anomaly-1",
        severity="critical",
    )

    await fresh_bus.publish_async(ev)
    # Небольшая задержка — handlers запускаются в thread pool
    done_flag.wait(timeout=3.0)

    # Событие должно быть в истории
    history = fresh_bus.get_history(event_type=ComplianceEventType.ANOMALY_DETECTED)
    assert any(e.event_id == ev.event_id for e in history)


# ── Тест 15: subscribe_all() ──────────────────────────────────────────────────

def test_subscribe_all_receives_all_types(fresh_bus: EventBus):
    """subscribe_all() должен получать события всех типов."""
    all_events: List[ComplianceEvent] = []
    all_received = threading.Event()

    def catch_all(e: ComplianceEvent) -> None:
        all_events.append(e)
        if len(all_events) >= 2:
            all_received.set()

    fresh_bus.subscribe_all(catch_all)

    ev1 = ComplianceEvent.create(
        event_type=ComplianceEventType.POLICY_REJECTED,
        entity_type="policy",
        entity_id="POL-002",
    )
    ev2 = ComplianceEvent.create(
        event_type=ComplianceEventType.VENDOR_REVIEW_DUE,
        entity_type="vendor",
        entity_id="VND-001",
    )

    fresh_bus.publish(ev1)
    fresh_bus.publish(ev2)

    all_received.wait(timeout=3.0)

    received_ids = [e.event_id for e in all_events]
    assert ev1.event_id in received_ids
    assert ev2.event_id in received_ids


# ── Тест 16: SlackEventHandler — нет webhook ─────────────────────────────────

def test_slack_handler_no_webhook(sla_breach_event: ComplianceEvent):
    """SlackEventHandler не должен падать если SLACK_WEBHOOK_URL не задан."""
    from event_handlers import SlackEventHandler

    handler = SlackEventHandler()

    critical_event = ComplianceEvent.create(
        event_type=ComplianceEventType.SLA_BREACH,
        entity_type="evidence",
        entity_id="ev-001",
        severity="critical",
    )

    # Без webhook — просто тихо пропускает
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("SLACK_WEBHOOK_URL", None)
        handler(critical_event)  # Не должен поднимать исключение


# ── Тест 17: SlackEventHandler — не critical ──────────────────────────────────

def test_slack_handler_skips_non_critical():
    """SlackEventHandler не должен отправлять уведомление при severity != critical."""
    from event_handlers import SlackEventHandler
    from slack_notifier import SlackNotifier

    handler = SlackEventHandler()
    info_event = ComplianceEvent.create(
        event_type=ComplianceEventType.EVIDENCE_ADDED,
        entity_type="evidence",
        entity_id="ev-001",
        severity="info",  # НЕ critical
    )

    with patch.object(SlackNotifier, "send_violation") as mock_send:
        handler(info_event)
        mock_send.assert_not_called()


# ── Тест 18: RiskEscalationHandler — PASS не создаёт риск ────────────────────

def test_risk_handler_skips_pass_status():
    """RiskEscalationHandler не должен создавать риск при статусе PASS."""
    from event_handlers import RiskEscalationHandler
    from risk_register import RiskRegister

    handler = RiskEscalationHandler()
    pass_event = ComplianceEvent.create(
        event_type=ComplianceEventType.CONTROL_STATUS_CHANGED,
        entity_type="control",
        entity_id="CC6.1",
        payload={"control_id": "CC6.1", "new_status": "PASS"},
        severity="info",
    )

    with patch.object(RiskRegister, "create") as mock_create:
        handler(pass_event)
        mock_create.assert_not_called()


# ── Тест 19: RiskEscalationHandler — FAIL создаёт риск ──────────────────────

def test_risk_handler_creates_risk_on_fail(control_fail_event: ComplianceEvent):
    """RiskEscalationHandler должен создать риск при статусе FAIL."""
    from event_handlers import RiskEscalationHandler
    from risk_register import RiskRegister

    handler = RiskEscalationHandler()

    mock_risk = {
        "id":       "RISK-TEST-001",
        "score":    20,
        "status":   "open",
        "title":    "Auto risk",
    }

    with patch.object(RiskRegister, "create", return_value=mock_risk) as mock_create, \
         patch.object(RiskRegister, "get_all", return_value=[]) as mock_get, \
         patch("event_handlers.get_event_bus") as mock_bus:
        mock_bus_instance = MagicMock()
        mock_bus.return_value = mock_bus_instance

        handler(control_fail_event)

        mock_create.assert_called_once()
        # Проверяем что риск создан для правильного контрола
        call_args = mock_create.call_args[0][0]
        assert "CC6.1" in call_args.get("title", "") or \
               call_args.get("control_id") == "CC6.1"


# ── Тест 20: SLABreachHandler ─────────────────────────────────────────────────

def test_sla_breach_handler_logs_to_decision_log(sla_breach_event: ComplianceEvent):
    """SLABreachHandler должен записать SLA breach в ai_decision_log."""
    from event_handlers import SLABreachHandler
    from ai_decision_log import AIDecisionLogger

    handler = SLABreachHandler()

    mock_record = MagicMock()
    with patch.object(AIDecisionLogger, "record", return_value=mock_record) as mock_log:
        handler(sla_breach_event)

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs.get("outcome") == "SLA_BREACH"


# ── Тест 21: Множество подписчиков на один тип ────────────────────────────────

def test_multiple_handlers_all_called(fresh_bus: EventBus):
    """Несколько handlers на один тип события должны все получить событие."""
    calls: List[str] = []
    events = [threading.Event(), threading.Event(), threading.Event()]

    def make_handler(name: str, done: threading.Event):
        def h(e: ComplianceEvent) -> None:
            calls.append(name)
            done.set()
        return h

    for i, ev in enumerate(events):
        fresh_bus.subscribe(
            ComplianceEventType.AUDIT_SCAN_COMPLETED,
            make_handler(f"handler_{i}", ev),
        )

    target = ComplianceEvent.create(
        event_type=ComplianceEventType.AUDIT_SCAN_COMPLETED,
        entity_type="scan",
        entity_id="scan-001",
    )
    fresh_bus.publish(target)

    for ev in events:
        ev.wait(timeout=3.0)

    assert "handler_0" in calls
    assert "handler_1" in calls
    assert "handler_2" in calls


# ── Тест 22: ComplianceEvent.to_dict() ───────────────────────────────────────

def test_compliance_event_to_dict_serialization(sample_event: ComplianceEvent):
    """to_dict() должен корректно сериализовать все поля."""
    d = sample_event.to_dict()

    assert d["event_id"] == sample_event.event_id
    assert d["event_type"] == ComplianceEventType.EVIDENCE_ADDED.value
    assert d["entity_type"] == "evidence"
    assert d["entity_id"] == "ev-001"
    assert d["actor"] == "test"
    assert d["severity"] == "info"
    assert isinstance(d["timestamp"], str)
    assert isinstance(d["payload"], dict)


# ── Тест 23: get_event_bus() singleton ───────────────────────────────────────

def test_get_event_bus_returns_singleton():
    """get_event_bus() должен возвращать один и тот же экземпляр."""
    import event_bus as eb_module

    # Временно сбрасываем singleton для теста
    original = eb_module._event_bus_instance
    eb_module._event_bus_instance = None

    try:
        bus1 = get_event_bus()
        bus2 = get_event_bus()
        assert bus1 is bus2, "get_event_bus() должен возвращать singleton"
    finally:
        eb_module._event_bus_instance = original


# ── Тест 24: FIFO история при переполнении ────────────────────────────────────

def test_history_fifo_eviction():
    """При переполнении FIFO-очереди старые события должны вытесняться."""
    from event_bus import _MAX_HISTORY

    bus = EventBus()
    bus.unsubscribe_all()

    # Публикуем maxlen + 10 событий
    first_event_id = None
    for i in range(_MAX_HISTORY + 10):
        ev = ComplianceEvent.create(
            event_type=ComplianceEventType.AUDIT_SCAN_COMPLETED,
            entity_type="scan",
            entity_id=f"scan-{i}",
        )
        if i == 0:
            first_event_id = ev.event_id
        bus.publish(ev)

    history = bus.get_history(limit=_MAX_HISTORY)
    ids = [e.event_id for e in history]

    # Первое событие должно быть вытеснено
    assert first_event_id not in ids, "Старое событие должно быть вытеснено FIFO"
    assert len(history) == _MAX_HISTORY


# ── Тест 25: Thread-safety при параллельной публикации ───────────────────────

def test_thread_safe_parallel_publish(fresh_bus: EventBus):
    """Параллельная публикация из нескольких потоков должна работать без ошибок."""
    results: List[str] = []
    done_flags = []

    def worker(thread_id: int) -> None:
        for i in range(10):
            ev = ComplianceEvent.create(
                event_type=ComplianceEventType.EVIDENCE_ADDED,
                entity_type="evidence",
                entity_id=f"ev-t{thread_id}-{i}",
                severity="info",
            )
            fresh_bus.publish(ev)
            results.append(ev.event_id)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    # Все 50 событий должны быть опубликованы без исключений
    assert len(results) == 50

    history = fresh_bus.get_history(limit=100)
    # Хотя бы большинство событий должны быть в истории
    history_ids = {e.event_id for e in history}
    overlap = len(set(results) & history_ids)
    assert overlap >= 40, f"Большинство параллельных событий должны быть в истории, получено {overlap}/50"
