"""
tests/test_event_sourcing.py — Тесты Event Sourcing + Replay Engine.

Покрывают:
  1.  SourcedEvent.to_dict() — корректная сериализация
  2.  SourcedEvent.from_dict() — корректная десериализация (roundtrip)
  3.  SourcedEvent.from_compliance_event() — bridge из ComplianceEvent
  4.  EventStore.append() — первое событие получает sequence_number=1
  5.  EventStore.append() — sequence_number монотонно возрастает
  6.  EventStore.append() — события НИКОГДА не теряются (count растёт)
  7.  EventStore.get_events_for_entity() — фильтрация по entity
  8.  EventStore.get_events_for_entity() — фильтрация с диапазоном дат
  9.  EventStore.get_events_since() — фильтрация от sequence_number
  10. EventStore.get_events_in_range() — фильтрация по occurred_at
  11. EventStore.get_causation_chain() — цепочка причинности
  12. EventStore.get_correlation_group() — группа по correlation_id
  13. ComplianceReplayEngine.replay_to() — пустой store → пустой snapshot
  14. ComplianceReplayEngine.replay_to() — корректный snapshot с событиями
  15. ComplianceReplayEngine.replay_to() — детерминизм (повторный вызов)
  16. ComplianceReplayEngine.replay_control() — история одного контроля
  17. ComplianceReplayEngine.compute_diff() — diff между снапшотами
  18. ComplianceReplayEngine.find_regression() — находит переход PASS→FAIL
  19. ComplianceReplayEngine.find_regression() — None если нет регрессии
  20. ComplianceReplayEngine.get_compliance_timeline() — timeline точек
  21. EventStore — thread-safety при параллельном append
  22. EventStore — персистентность (reload из файла)
  23. _apply_event — EVIDENCE_ADDED обновляет count и статус
  24. _apply_event — RISK_CREATED добавляет risk_score
  25. _generate_timeline_points — корректные точки для day-resolution
"""

from __future__ import annotations

import sys
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock

import pytest

# Добавляем корень проекта в path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from event_bus import ComplianceEvent, ComplianceEventType
from event_sourcing import (
    ComplianceReplayEngine,
    ReplaySnapshot,
    EventStore,
    RegressionEvent,
    SnapshotDiff,
    SourcedEvent,
    TimelinePoint,
    _apply_event,
    _generate_timeline_points,
    reset_singletons_for_testing,
)


# ── Фикстуры ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_singletons():
    """Сбрасываем синглтоны перед каждым тестом для изоляции."""
    reset_singletons_for_testing()
    yield
    reset_singletons_for_testing()


@pytest.fixture
def tmp_store(tmp_path: Path) -> EventStore:
    """EventStore с временным JSON-файлом в tmp_path."""
    store = EventStore(store_path=tmp_path / "event_store.json")
    return store


@pytest.fixture
def engine(tmp_store: EventStore) -> ComplianceReplayEngine:
    """ComplianceReplayEngine с временным store."""
    return ComplianceReplayEngine(store=tmp_store)


def _dt(days_ago: int = 0, hours_ago: int = 0) -> datetime:
    """Возвращает timezone-aware UTC datetime N дней/часов назад."""
    return datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)


def _make_sourced(
    event_type: str = ComplianceEventType.CONTROL_STATUS_CHANGED.value,
    entity_type: str = "control",
    entity_id: str = "CC6.1",
    actor: str = "system",
    payload: Optional[dict] = None,
    occurred_at: Optional[datetime] = None,
    causation_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> SourcedEvent:
    """Создаёт тестовый SourcedEvent с seq=0 (EventStore назначит правильный)."""
    now = datetime.now(timezone.utc)
    return SourcedEvent(
        event_id=str(uuid.uuid4()),
        sequence_number=0,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        payload=payload or {},
        occurred_at=occurred_at or now,
        recorded_at=now,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


def _make_status_event(
    control_id: str,
    status: str,
    occurred_at: Optional[datetime] = None,
    causation_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> SourcedEvent:
    """Вспомогательная: создаёт CONTROL_STATUS_CHANGED событие."""
    return _make_sourced(
        event_type=ComplianceEventType.CONTROL_STATUS_CHANGED.value,
        entity_type="control",
        entity_id=control_id,
        payload={"new_status": status, "control_id": control_id},
        occurred_at=occurred_at,
        causation_id=causation_id,
        correlation_id=correlation_id,
    )


# ── Тест 1: SourcedEvent.to_dict() ────────────────────────────────────────────

def test_sourced_event_to_dict():
    """SourcedEvent.to_dict() возвращает корректный словарь."""
    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    event = SourcedEvent(
        event_id=event_id,
        sequence_number=42,
        event_type=ComplianceEventType.EVIDENCE_ADDED.value,
        entity_type="evidence",
        entity_id="ev-001",
        actor="agent:okta",
        payload={"control_id": "CC6.1"},
        occurred_at=now,
        recorded_at=now,
        causation_id="parent-id",
        correlation_id="session-123",
    )
    d = event.to_dict()
    assert d["event_id"] == event_id
    assert d["sequence_number"] == 42
    assert d["event_type"] == ComplianceEventType.EVIDENCE_ADDED.value
    assert d["entity_type"] == "evidence"
    assert d["causation_id"] == "parent-id"
    assert d["correlation_id"] == "session-123"
    assert d["payload"] == {"control_id": "CC6.1"}


# ── Тест 2: SourcedEvent.from_dict() roundtrip ────────────────────────────────

def test_sourced_event_from_dict_roundtrip():
    """SourcedEvent.to_dict() → from_dict() → идентичный объект."""
    now = datetime.now(timezone.utc)
    original = SourcedEvent(
        event_id=str(uuid.uuid4()),
        sequence_number=7,
        event_type=ComplianceEventType.RISK_CREATED.value,
        entity_type="risk",
        entity_id="risk-99",
        actor="human:admin@test.com",
        payload={"severity": 4},
        occurred_at=now,
        recorded_at=now,
        causation_id=None,
        correlation_id="txn-xyz",
    )
    restored = SourcedEvent.from_dict(original.to_dict())
    assert restored.event_id == original.event_id
    assert restored.sequence_number == original.sequence_number
    assert restored.event_type == original.event_type
    assert restored.entity_id == original.entity_id
    assert restored.payload == original.payload
    assert restored.correlation_id == original.correlation_id
    assert restored.causation_id is None


# ── Тест 3: SourcedEvent.from_compliance_event() ────────────────────────────────

def test_sourced_event_from_compliance_event():
    """from_compliance_event() корректно конвертирует ComplianceEvent."""
    ce = ComplianceEvent.create(
        event_type=ComplianceEventType.EVIDENCE_ADDED,
        entity_type="evidence",
        entity_id="ev-123",
        actor="system",
        payload={"control_id": "CC6.1"},
    )
    se = SourcedEvent.from_compliance_event(ce, sequence_number=5, causation_id="parent-evt")
    assert se.event_id == ce.event_id
    assert se.sequence_number == 5
    assert se.event_type == ComplianceEventType.EVIDENCE_ADDED.value
    assert se.causation_id == "parent-evt"
    assert se.payload["control_id"] == "CC6.1"


# ── Тест 4: EventStore.append() — первый seq=1 ────────────────────────────────

def test_event_store_first_sequence_number(tmp_store: EventStore):
    """Первое событие получает sequence_number=1."""
    event = _make_sourced()
    appended = tmp_store.append(event)
    assert appended.sequence_number == 1


# ── Тест 5: EventStore.append() — монотонность ─────────────────────────────────

def test_event_store_monotonic_sequence(tmp_store: EventStore):
    """sequence_number монотонно возрастает при последовательных append."""
    seqs = []
    for _ in range(5):
        appended = tmp_store.append(_make_sourced())
        seqs.append(appended.sequence_number)

    assert seqs == sorted(seqs), "sequence_numbers должны возрастать"
    assert seqs == list(range(1, 6)), "sequence_numbers должны быть 1..5"


# ── Тест 6: EventStore — count растёт ─────────────────────────────────────────

def test_event_store_count_grows(tmp_store: EventStore):
    """count() увеличивается при каждом append."""
    assert tmp_store.count() == 0
    for i in range(3):
        tmp_store.append(_make_sourced())
        assert tmp_store.count() == i + 1


# ── Тест 7: EventStore.get_events_for_entity() ────────────────────────────────

def test_event_store_get_events_for_entity(tmp_store: EventStore):
    """get_events_for_entity() фильтрует по entity_type и entity_id."""
    tmp_store.append(_make_sourced(entity_type="control", entity_id="CC6.1"))
    tmp_store.append(_make_sourced(entity_type="control", entity_id="CC6.2"))
    tmp_store.append(_make_sourced(entity_type="evidence", entity_id="ev-001"))

    result = tmp_store.get_events_for_entity("control", "CC6.1")
    assert len(result) == 1
    assert result[0].entity_id == "CC6.1"

    result_ev = tmp_store.get_events_for_entity("evidence", "ev-001")
    assert len(result_ev) == 1


# ── Тест 8: get_events_for_entity() с диапазоном дат ────────────────────────

def test_event_store_get_events_for_entity_date_range(tmp_store: EventStore):
    """get_events_for_entity() с from_dt/to_dt фильтрует по occurred_at."""
    old_dt = _dt(days_ago=10)
    new_dt = _dt(days_ago=1)

    tmp_store.append(_make_sourced(entity_id="CC6.1", occurred_at=old_dt))
    tmp_store.append(_make_sourced(entity_id="CC6.1", occurred_at=new_dt))

    # Только новое событие
    result = tmp_store.get_events_for_entity(
        "control", "CC6.1",
        from_dt=_dt(days_ago=5),
        to_dt=datetime.now(timezone.utc),
    )
    assert len(result) == 1
    assert result[0].occurred_at == new_dt


# ── Тест 9: EventStore.get_events_since() ─────────────────────────────────────

def test_event_store_get_events_since(tmp_store: EventStore):
    """get_events_since(seq) возвращает события начиная с seq включительно."""
    for _ in range(5):
        tmp_store.append(_make_sourced())

    result = tmp_store.get_events_since(3)
    assert all(e.sequence_number >= 3 for e in result)
    assert len(result) == 3  # seq 3, 4, 5


# ── Тест 10: EventStore.get_events_in_range() ─────────────────────────────────

def test_event_store_get_events_in_range(tmp_store: EventStore):
    """get_events_in_range() возвращает события в диапазоне occurred_at."""
    t_old  = _dt(days_ago=10)
    t_mid  = _dt(days_ago=5)
    t_new  = _dt(days_ago=1)

    tmp_store.append(_make_sourced(occurred_at=t_old))
    tmp_store.append(_make_sourced(occurred_at=t_mid))
    tmp_store.append(_make_sourced(occurred_at=t_new))

    result = tmp_store.get_events_in_range(
        from_dt=_dt(days_ago=7),
        to_dt=_dt(days_ago=0),
    )
    # Должны попасть t_mid и t_new, но не t_old
    assert len(result) == 2


# ── Тест 11: EventStore.get_causation_chain() ─────────────────────────────────

def test_event_store_causation_chain(tmp_store: EventStore):
    """get_causation_chain() возвращает цепочку от первопричины к следствию."""
    root = tmp_store.append(_make_sourced(entity_id="root"))
    child = tmp_store.append(_make_sourced(
        entity_id="child",
        causation_id=root.event_id,
    ))
    grandchild = tmp_store.append(_make_sourced(
        entity_id="grandchild",
        causation_id=child.event_id,
    ))

    chain = tmp_store.get_causation_chain(grandchild.event_id)
    assert len(chain) == 3
    assert chain[0].event_id == root.event_id       # первопричина первой
    assert chain[1].event_id == child.event_id
    assert chain[2].event_id == grandchild.event_id


# ── Тест 12: EventStore.get_correlation_group() ─────────────────────────────

def test_event_store_correlation_group(tmp_store: EventStore):
    """get_correlation_group() возвращает события одной корреляционной группы."""
    corr_id = "session-abc"
    tmp_store.append(_make_sourced(correlation_id=corr_id))
    tmp_store.append(_make_sourced(correlation_id=corr_id))
    tmp_store.append(_make_sourced(correlation_id="other-session"))

    group = tmp_store.get_correlation_group(corr_id)
    assert len(group) == 2
    assert all(e.correlation_id == corr_id for e in group)


# ── Тест 13: replay_to() — пустой store ──────────────────────────────────────

def test_replay_to_empty_store(engine: ComplianceReplayEngine):
    """replay_to() на пустом store возвращает snapshot с пустыми данными."""
    snapshot = engine.replay_to(datetime.now(timezone.utc))
    assert snapshot.control_statuses == {}
    assert snapshot.evidence_counts == {}
    assert snapshot.risk_scores == {}
    assert snapshot.overall_score == 0.0


# ── Тест 14: replay_to() — корректный snapshot ────────────────────────────────

def test_replay_to_with_events(tmp_store: EventStore, engine: ComplianceReplayEngine):
    """replay_to() корректно применяет события и возвращает актуальный snapshot."""
    t1 = _dt(hours_ago=5)
    t2 = _dt(hours_ago=3)

    tmp_store.append(_make_status_event("CC6.1", "PASS", occurred_at=t1))
    tmp_store.append(_make_status_event("CC6.2", "FAIL", occurred_at=t2))

    snapshot = engine.replay_to(datetime.now(timezone.utc))
    assert snapshot.control_statuses["CC6.1"] == "PASS"
    assert snapshot.control_statuses["CC6.2"] == "FAIL"
    assert snapshot.overall_score == pytest.approx(50.0, abs=0.1)


# ── Тест 15: replay_to() — детерминизм ───────────────────────────────────────

def test_replay_to_determinism(tmp_store: EventStore, engine: ComplianceReplayEngine):
    """Повторный вызов replay_to() с теми же данными даёт одинаковый результат."""
    tmp_store.append(_make_status_event("CC6.1", "PASS"))

    target = datetime.now(timezone.utc)
    snap1 = engine.replay_to(target)
    snap2 = engine.replay_to(target)

    assert snap1.control_statuses == snap2.control_statuses
    assert snap1.overall_score == snap2.overall_score


# ── Тест 16: replay_control() — история контроля ─────────────────────────────

def test_replay_control_history(tmp_store: EventStore, engine: ComplianceReplayEngine):
    """replay_control() возвращает корректную хронологию переходов статуса."""
    t1 = _dt(hours_ago=10)
    t2 = _dt(hours_ago=5)
    t3 = _dt(hours_ago=1)

    tmp_store.append(_make_status_event("CC6.1", "PASS", occurred_at=t1))
    tmp_store.append(_make_status_event("CC6.1", "FAIL", occurred_at=t2))
    tmp_store.append(_make_status_event("CC6.1", "PASS", occurred_at=t3))
    # Другой контроль — не должен попасть
    tmp_store.append(_make_status_event("CC6.2", "PASS", occurred_at=t1))

    history = engine.replay_control("CC6.1", datetime.now(timezone.utc))
    assert len(history.transitions) == 3
    assert history.transitions[0]["to_status"] == "PASS"
    assert history.transitions[1]["to_status"] == "FAIL"
    assert history.transitions[2]["to_status"] == "PASS"


# ── Тест 17: compute_diff() ───────────────────────────────────────────────────

def test_compute_diff(engine: ComplianceReplayEngine):
    """compute_diff() корректно вычисляет разницу между двумя snapshot."""
    snap_a = ReplaySnapshot(
        snapshot_at=_dt(days_ago=5),
        control_statuses={"CC6.1": "PASS", "CC6.2": "PASS"},
        evidence_counts={"CC6.1": 3},
        risk_scores={"risk-1": 3},
        overall_score=100.0,
    )
    snap_b = ReplaySnapshot(
        snapshot_at=datetime.now(timezone.utc),
        control_statuses={"CC6.1": "FAIL", "CC6.2": "PASS"},
        evidence_counts={"CC6.1": 2},
        risk_scores={"risk-2": 5},
        overall_score=50.0,
    )
    diff = engine.compute_diff(snap_a, snap_b)
    assert diff.score_delta == pytest.approx(-50.0, abs=0.1)
    assert len(diff.changed) == 1
    assert diff.changed[0]["control_id"] == "CC6.1"
    assert diff.changed[0]["from_status"] == "PASS"
    assert diff.changed[0]["to_status"] == "FAIL"
    assert "risk-2" in diff.new_risks
    assert "risk-1" in diff.resolved_risks


# ── Тест 18: find_regression() — находит PASS→FAIL ───────────────────────────

def test_find_regression_found(tmp_store: EventStore, engine: ComplianceReplayEngine):
    """find_regression() находит первый переход PASS→FAIL в диапазоне."""
    t0 = _dt(hours_ago=12)
    t1 = _dt(hours_ago=6)
    t2 = _dt(hours_ago=3)

    tmp_store.append(_make_status_event("CC6.1", "PASS", occurred_at=t0))
    tmp_store.append(_make_status_event("CC6.1", "FAIL", occurred_at=t1))
    tmp_store.append(_make_status_event("CC6.1", "PASS", occurred_at=t2))

    regression = engine.find_regression(
        "CC6.1",
        from_dt=_dt(hours_ago=8),
        to_dt=datetime.now(timezone.utc),
    )
    assert regression is not None
    assert regression.control_id == "CC6.1"
    # occurred_at должен быть в [t1 - epsilon, t1 + epsilon]
    assert abs((regression.occurred_at - t1).total_seconds()) < 1


# ── Тест 19: find_regression() — нет регрессии ────────────────────────────────

def test_find_regression_not_found(tmp_store: EventStore, engine: ComplianceReplayEngine):
    """find_regression() возвращает None если контроль не деградировал."""
    tmp_store.append(_make_status_event("CC6.1", "PASS", occurred_at=_dt(hours_ago=5)))
    tmp_store.append(_make_status_event("CC6.1", "PASS", occurred_at=_dt(hours_ago=2)))

    result = engine.find_regression(
        "CC6.1",
        from_dt=_dt(hours_ago=10),
        to_dt=datetime.now(timezone.utc),
    )
    assert result is None


# ── Тест 20: get_compliance_timeline() ────────────────────────────────────────

def test_compliance_timeline(tmp_store: EventStore, engine: ComplianceReplayEngine):
    """get_compliance_timeline() возвращает список TimelinePoint."""
    # Добавляем событие в середине диапазона
    mid = _dt(days_ago=3)
    tmp_store.append(_make_status_event("CC6.1", "PASS", occurred_at=mid))

    from_dt = _dt(days_ago=5)
    to_dt   = _dt(days_ago=1)
    points  = engine.get_compliance_timeline(from_dt, to_dt, resolution="day")

    assert len(points) >= 2  # минимум from_dt и to_dt
    assert all(isinstance(p, TimelinePoint) for p in points)
    # Все score в диапазоне [0, 100]
    assert all(0.0 <= p.score <= 100.0 for p in points)
    # Последняя точка должна иметь ненулевой score (событие было в диапазоне)
    assert points[-1].score > 0.0 or points[-1].total == 0


# ── Тест 21: Thread-safety при параллельном append ────────────────────────────

def test_event_store_thread_safety(tmp_store: EventStore):
    """EventStore.append() thread-safe: никаких дублирующихся sequence_number."""
    results = []
    errors = []

    def worker():
        try:
            for _ in range(10):
                appended = tmp_store.append(_make_sourced())
                results.append(appended.sequence_number)
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Ошибки в потоках: {errors}"
    # 5 потоков × 10 событий = 50 событий
    assert len(results) == 50
    # Все sequence_number уникальны
    assert len(set(results)) == 50


# ── Тест 22: Персистентность (reload из файла) ─────────────────────────────────

def test_event_store_persistence(tmp_path: Path):
    """События сохраняются в файл и корректно перезагружаются."""
    store_path = tmp_path / "test_store.json"

    # Первый store: записываем события
    store1 = EventStore(store_path=store_path)
    e1 = store1.append(_make_status_event("CC6.1", "PASS"))
    e2 = store1.append(_make_status_event("CC6.2", "FAIL"))

    # Второй store (тот же файл): читаем
    store2 = EventStore(store_path=store_path)
    all_events = store2.get_all()

    assert len(all_events) == 2
    assert all_events[0].event_id == e1.event_id
    assert all_events[1].event_id == e2.event_id
    assert store2.count() == 2

    # sequence_number продолжается корректно
    e3 = store2.append(_make_sourced())
    assert e3.sequence_number == 3


# ── Тест 23: _apply_event — EVIDENCE_ADDED ────────────────────────────────────

def test_apply_event_evidence_added():
    """_apply_event(EVIDENCE_ADDED) увеличивает count и устанавливает PASS."""
    state = {
        "control_statuses": {"CC6.1": "UNKNOWN"},
        "evidence_counts":  {"CC6.1": 0},
        "risk_scores":      {},
    }
    event = _make_sourced(
        event_type=ComplianceEventType.EVIDENCE_ADDED.value,
        entity_type="evidence",
        entity_id="ev-001",
        payload={"control_id": "CC6.1"},
    )
    new_state = _apply_event(state, event)

    assert new_state["evidence_counts"]["CC6.1"] == 1
    assert new_state["control_statuses"]["CC6.1"] == "PASS"
    # Оригинальный state не мутирован
    assert state["control_statuses"]["CC6.1"] == "UNKNOWN"


# ── Тест 24: _apply_event — RISK_CREATED ──────────────────────────────────────

def test_apply_event_risk_created():
    """_apply_event(RISK_CREATED) добавляет risk_score."""
    state = {
        "control_statuses": {},
        "evidence_counts":  {},
        "risk_scores":      {},
    }
    event = _make_sourced(
        event_type=ComplianceEventType.RISK_CREATED.value,
        entity_type="risk",
        entity_id="risk-42",
        payload={"severity": 4},
    )
    new_state = _apply_event(state, event)

    assert new_state["risk_scores"]["risk-42"] == 4
    assert new_state["risk_scores"] is not state["risk_scores"]  # иммутабельность


# ── Тест 25: _generate_timeline_points — day resolution ──────────────────────

def test_generate_timeline_points_day():
    """_generate_timeline_points() с resolution=day генерирует ежедневные точки."""
    from_dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    to_dt   = datetime(2026, 1, 5, tzinfo=timezone.utc)

    points = _generate_timeline_points(from_dt, to_dt, "day")

    # 1, 2, 3, 4, 5 января = 5 точек
    assert len(points) >= 5
    # Первая точка = from_dt
    assert points[0] == from_dt
    # Последняя точка ≥ to_dt
    assert points[-1] >= to_dt
    # Шаг ровно 1 день (для первых пар)
    for i in range(1, min(4, len(points))):
        delta = (points[i] - points[i - 1]).total_seconds()
        assert abs(delta - 86400) < 1, f"Шаг {delta}с != 86400с (1 день)"
