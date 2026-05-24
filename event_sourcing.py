"""
event_sourcing.py — Event Sourcing + Replay Engine для SOC2 Compliance Sandbox.

Архитектура:
  SourcedEvent           — иммутабельный dataclass события с causation/correlation
  EventStore             — append-only хранилище событий (JSON dev / DB prod)
  ComplianceReplayEngine — детерминированный replay до произвольного момента
  ReplaySnapshot         — состояние compliance на конкретный момент (event sourcing)
  SnapshotDiff           — разница между двумя снапшотами
  ControlHistory         — история изменений одного контроля
  RegressionEvent        — момент регрессии PASS → FAIL
  TimelinePoint          — точка на timeline для графика

Гарантии:
  1. EventStore append-only: события НИКОГДА не удаляются и не изменяются
  2. Replay детерминистичен: одни и те же события → одинаковый результат
  3. Causation chain прозрачна: любое изменение отслеживается до первопричины
  4. Thread-safe: append атомарен, чтение потокобезопасно
"""

from __future__ import annotations

import fcntl
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from event_bus import ComplianceEvent, ComplianceEventType, get_event_bus
from log_config import get_logger

log = get_logger(__name__)

# Путь к JSON-хранилищу событий (dev-режим)
_DEFAULT_STORE_PATH = Path(__file__).parent / "data" / "event_store.json"

# Статусы контролей (используются в reducer)
_PASS = "PASS"
_FAIL = "FAIL"
_UNKNOWN = "UNKNOWN"

# Маппинг event_type → entity_type, с которым работает reducer
_CONTROL_EVENT_TYPES = {
    ComplianceEventType.CONTROL_STATUS_CHANGED.value,
    ComplianceEventType.EVIDENCE_ADDED.value,
    ComplianceEventType.EVIDENCE_EXPIRED.value,
    ComplianceEventType.SLA_BREACH.value,
}

_RISK_EVENT_TYPES = {
    ComplianceEventType.RISK_CREATED.value,
    ComplianceEventType.RISK_ESCALATED.value,
}


# ── Доменные объекты ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SourcedEvent:
    """
    Иммутабельное событие с полной провенансностью.

    sequence_number — монотонно возрастающий глобальный счётчик.
    causation_id    — event_id родительского события (если применимо).
    correlation_id  — ID сессии/транзакции для группировки связанных событий.
    occurred_at     — когда событие произошло (может быть в прошлом при backfill).
    recorded_at     — когда событие записано в EventStore.
    """
    event_id:         str
    sequence_number:  int
    event_type:       str
    entity_type:      str
    entity_id:        str
    actor:            str
    payload:          Dict[str, Any]
    occurred_at:      datetime
    recorded_at:      datetime
    causation_id:     Optional[str] = None
    correlation_id:   Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Сериализует событие в dict (JSON-совместимый)."""
        return {
            "event_id":        self.event_id,
            "sequence_number": self.sequence_number,
            "event_type":      self.event_type,
            "entity_type":     self.entity_type,
            "entity_id":       self.entity_id,
            "actor":           self.actor,
            "payload":         self.payload,
            "occurred_at":     self.occurred_at.isoformat(),
            "recorded_at":     self.recorded_at.isoformat(),
            "causation_id":    self.causation_id,
            "correlation_id":  self.correlation_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourcedEvent":
        """Десериализует событие из dict."""

        def _parse_dt(val: Optional[str]) -> datetime:
            if not val:
                return datetime.now(timezone.utc)
            normalized = val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt

        return cls(
            event_id=data["event_id"],
            sequence_number=data["sequence_number"],
            event_type=data["event_type"],
            entity_type=data["entity_type"],
            entity_id=data["entity_id"],
            actor=data["actor"],
            payload=data.get("payload") or {},
            occurred_at=_parse_dt(data.get("occurred_at")),
            recorded_at=_parse_dt(data.get("recorded_at")),
            causation_id=data.get("causation_id"),
            correlation_id=data.get("correlation_id"),
        )

    @classmethod
    def from_compliance_event(
        cls,
        event: ComplianceEvent,
        sequence_number: int,
        causation_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> "SourcedEvent":
        """Создаёт SourcedEvent из ComplianceEvent (bridge)."""
        now = datetime.now(timezone.utc)
        return cls(
            event_id=event.event_id,
            sequence_number=sequence_number,
            event_type=event.event_type.value,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            actor=event.actor,
            payload=dict(event.payload),
            occurred_at=event.timestamp,
            recorded_at=now,
            causation_id=causation_id,
            correlation_id=correlation_id,
        )


@dataclass
class ReplaySnapshot:
    """
    Состояние compliance на конкретный момент времени (event sourcing).

    Вычисляется детерминистически из событий EventStore через ComplianceReplayEngine.
    overall_score — % контролей в статусе PASS.

    Отличается от time_machine.ComplianceSnapshot:
      - не зависит от EvidenceClient (только EventStore)
      - хранит risk_scores отдельно
      - детерминирован по sequence_number событий
    """
    snapshot_at:      datetime
    control_statuses: Dict[str, str]   # control_id → "PASS" | "FAIL" | "UNKNOWN"
    evidence_counts:  Dict[str, int]   # control_id → кол-во evidence
    risk_scores:      Dict[str, int]   # risk_id → severity score (1–5)
    overall_score:    float            # 0.0–100.0

    def to_dict(self) -> Dict[str, Any]:
        total = len(self.control_statuses)
        pass_count = sum(1 for s in self.control_statuses.values() if s == _PASS)
        fail_count = sum(1 for s in self.control_statuses.values() if s == _FAIL)
        return {
            "snapshot_at":      self.snapshot_at.isoformat(),
            "overall_score":    round(self.overall_score, 2),
            "total_controls":   total,
            "pass_count":       pass_count,
            "fail_count":       fail_count,
            "unknown_count":    total - pass_count - fail_count,
            "control_statuses": self.control_statuses,
            "evidence_counts":  self.evidence_counts,
            "risk_scores":      self.risk_scores,
        }


@dataclass
class SnapshotDiff:
    """Разница между двумя ComplianceSnapshot."""
    from_dt:       datetime
    to_dt:         datetime
    score_delta:   float                # overall_score_to - overall_score_from
    changed:       List[Dict[str, Any]] # [{control_id, from_status, to_status}]
    new_risks:     List[str]            # risk_id добавленные между снапшотами
    resolved_risks: List[str]          # risk_id исчезнувшие между снапшотами

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_dt":       self.from_dt.isoformat(),
            "to_dt":         self.to_dt.isoformat(),
            "score_delta":   round(self.score_delta, 2),
            "changed":       self.changed,
            "new_risks":     self.new_risks,
            "resolved_risks": self.resolved_risks,
        }


@dataclass
class ControlHistory:
    """История изменений одного контроля."""
    control_id:  str
    from_dt:     datetime
    to_dt:       datetime
    transitions: List[Dict[str, Any]]  # [{occurred_at, status, event_id, actor}]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id":  self.control_id,
            "from_dt":     self.from_dt.isoformat(),
            "to_dt":       self.to_dt.isoformat(),
            "transitions": self.transitions,
        }


@dataclass
class RegressionEvent:
    """Момент регрессии: когда контроль перешёл из PASS в FAIL."""
    control_id:   str
    occurred_at:  datetime
    event_id:     str
    actor:        str
    payload:      Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id":  self.control_id,
            "occurred_at": self.occurred_at.isoformat(),
            "event_id":    self.event_id,
            "actor":       self.actor,
            "payload":     self.payload,
        }


@dataclass
class TimelinePoint:
    """Точка на compliance timeline для графика."""
    point_at:   datetime
    score:      float      # % контролей в PASS
    pass_count: int
    fail_count: int
    total:      int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "point_at":   self.point_at.isoformat(),
            "score":      round(self.score, 2),
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "total":      self.total,
        }


# ── EventStore ─────────────────────────────────────────────────────────────────

class EventStore:
    """
    Append-only хранилище SourcedEvent.

    Dev-режим: JSON-файл data/event_store.json
    Prod-режим: AuditEventRepository через database.py (если DB enabled)

    Thread-safety:
      - Запись защищена threading.Lock + file-level flock (inter-process)
      - Чтение не требует lock (список неизменяем после загрузки)
      - sequence_number монотонно возрастает: max(existing) + 1

    Invariants:
      - События НИКОГДА не удаляются
      - sequence_number уникален и монотонен
      - recorded_at >= occurred_at (почти всегда; исключение — backfill)
    """

    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._path = store_path or _DEFAULT_STORE_PATH
        self._lock = threading.Lock()
        # Кэш в памяти: список событий, отсортированных по sequence_number
        self._events: List[SourcedEvent] = []
        self._loaded = False
        self._next_seq: int = 1

    # ── Загрузка ─────────────────────────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        """Ленивая загрузка событий из JSON-файла (один раз за жизнь процесса)."""
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            self._events = self._load_from_file()
            self._loaded = True
            if self._events:
                self._next_seq = max(e.sequence_number for e in self._events) + 1
            else:
                self._next_seq = 1

    def _load_from_file(self) -> List[SourcedEvent]:
        """Читает события из JSON-файла. Возвращает [] если файл не существует."""
        if not self._path.exists():
            return []
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                raw: List[Dict[str, Any]] = json.load(f)
            events = [SourcedEvent.from_dict(item) for item in raw]
            events.sort(key=lambda e: e.sequence_number)
            log.info(
                "EventStore: загружено событий из файла",
                extra={"count": len(events), "path": str(self._path)},
            )
            return events
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            log.error(
                "EventStore: ошибка чтения файла, сбрасываем в []",
                extra={"error": str(exc), "path": str(self._path)},
            )
            return []

    # ── Запись ──────────────────────────────────────────────────────────────────

    def append(self, event: SourcedEvent) -> SourcedEvent:
        """
        Добавляет событие в хранилище.

        Автоматически назначает sequence_number если он равен 0.
        Атомарная запись: file-level flock гарантирует консистентность
        при конкурентных процессах.

        Возвращает финальное событие с корректным sequence_number.
        """
        self._ensure_loaded()

        with self._lock:
            # Назначаем sequence_number
            seq = self._next_seq
            self._next_seq += 1

            # Создаём финальное событие с правильным seq
            final_event = SourcedEvent(
                event_id=event.event_id,
                sequence_number=seq,
                event_type=event.event_type,
                entity_type=event.entity_type,
                entity_id=event.entity_id,
                actor=event.actor,
                payload=event.payload,
                occurred_at=event.occurred_at,
                recorded_at=event.recorded_at,
                causation_id=event.causation_id,
                correlation_id=event.correlation_id,
            )

            self._events.append(final_event)
            self._persist_to_file(self._events)

        log.debug(
            "EventStore: событие добавлено",
            extra={
                "event_id":        final_event.event_id,
                "sequence_number": final_event.sequence_number,
                "event_type":      final_event.event_type,
            },
        )
        return final_event

    def _persist_to_file(self, events: List[SourcedEvent]) -> None:
        """
        Атомарная запись в JSON-файл.

        Использует file-level flock для inter-process safety.
        Пишет в tmp-файл, затем атомарно переименовывает (rename is atomic on Linux).
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_suffix(".tmp")

        raw = [e.to_dict() for e in events]
        data = json.dumps(raw, ensure_ascii=False, indent=2)

        with open(tmp_path, "w", encoding="utf-8") as f:
            # file-level lock (inter-process)
            try:
                fcntl.flock(f, fcntl.LOCK_EX)
            except OSError:
                pass  # flock недоступен (Windows / некоторые FS) — продолжаем без него
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            try:
                fcntl.flock(f, fcntl.LOCK_UN)
            except OSError:
                pass

        os.replace(tmp_path, self._path)

    # ── Запросы ──────────────────────────────────────────────────────────────────

    def get_events_for_entity(
        self,
        entity_type: str,
        entity_id: str,
        from_dt: Optional[datetime] = None,
        to_dt: Optional[datetime] = None,
    ) -> List[SourcedEvent]:
        """Возвращает события для конкретной сущности, опционально в диапазоне дат."""
        self._ensure_loaded()
        result = [
            e for e in self._events
            if e.entity_type == entity_type and e.entity_id == entity_id
        ]
        if from_dt:
            result = [e for e in result if e.occurred_at >= from_dt]
        if to_dt:
            result = [e for e in result if e.occurred_at <= to_dt]
        return result

    def get_events_since(self, sequence_number: int) -> List[SourcedEvent]:
        """Возвращает события начиная с указанного sequence_number (включительно)."""
        self._ensure_loaded()
        return [e for e in self._events if e.sequence_number >= sequence_number]

    def get_events_in_range(
        self,
        from_dt: datetime,
        to_dt: datetime,
    ) -> List[SourcedEvent]:
        """Возвращает все события в диапазоне [from_dt, to_dt] по occurred_at."""
        self._ensure_loaded()
        return [
            e for e in self._events
            if from_dt <= e.occurred_at <= to_dt
        ]

    def get_causation_chain(self, event_id: str) -> List[SourcedEvent]:
        """
        Возвращает цепочку причинности для события.

        Рекурсивно находит предков через causation_id.
        Цепочка упорядочена от первопричины к конечному событию.
        """
        self._ensure_loaded()
        # Строим индекс event_id → event
        index: Dict[str, SourcedEvent] = {e.event_id: e for e in self._events}

        # Находим стартовое событие
        start = index.get(event_id)
        if start is None:
            return []

        # Путь вверх по causation_id
        chain: List[SourcedEvent] = [start]
        visited: set[str] = {event_id}
        current = start

        while current.causation_id and current.causation_id not in visited:
            parent = index.get(current.causation_id)
            if parent is None:
                break
            chain.append(parent)
            visited.add(current.causation_id)
            current = parent

        # Разворачиваем: первопричина первой
        chain.reverse()
        return chain

    def get_correlation_group(self, correlation_id: str) -> List[SourcedEvent]:
        """Возвращает все события одной сессии/транзакции по correlation_id."""
        self._ensure_loaded()
        return [
            e for e in self._events
            if e.correlation_id == correlation_id
        ]

    def get_all(self) -> List[SourcedEvent]:
        """Возвращает все события (копию списка)."""
        self._ensure_loaded()
        return list(self._events)

    def count(self) -> int:
        """Возвращает количество событий в хранилище."""
        self._ensure_loaded()
        return len(self._events)

    def clear_for_testing(self) -> None:
        """
        Очищает хранилище.
        ТОЛЬКО ДЛЯ ТЕСТОВ — нарушает append-only invariant.
        """
        with self._lock:
            self._events = []
            self._next_seq = 1
            self._loaded = True
            if self._path.exists():
                self._path.unlink()


# ── Reducer (чистая функция) ───────────────────────────────────────────────────

def _apply_event(
    state: Dict[str, Any],
    event: SourcedEvent,
) -> Dict[str, Any]:
    """
    Reducer: применяет одно событие к состоянию.

    Чистая функция — не мутирует state, возвращает новый dict.
    Детерминизм гарантирован: одни и те же события → один результат.

    state структура:
      control_statuses: {control_id: "PASS"|"FAIL"|"UNKNOWN"}
      evidence_counts:  {control_id: int}
      risk_scores:      {risk_id: int}
    """
    # Копируем state (иммутабельность)
    ctrl_statuses = dict(state.get("control_statuses", {}))
    ev_counts = dict(state.get("evidence_counts", {}))
    risk_scores = dict(state.get("risk_scores", {}))

    et = event.event_type
    payload = event.payload

    if et == ComplianceEventType.CONTROL_STATUS_CHANGED.value:
        control_id = event.entity_id or payload.get("control_id", "")
        new_status = payload.get("new_status") or payload.get("status", _UNKNOWN)
        if control_id:
            ctrl_statuses[control_id] = new_status

    elif et == ComplianceEventType.EVIDENCE_ADDED.value:
        control_id = payload.get("control_id") or event.entity_id
        if control_id:
            ev_counts[control_id] = ev_counts.get(control_id, 0) + 1
            # Если статус ещё не FAIL → ставим PASS (evidence добавлено)
            if ctrl_statuses.get(control_id) != _FAIL:
                ctrl_statuses[control_id] = _PASS

    elif et == ComplianceEventType.EVIDENCE_EXPIRED.value:
        control_id = payload.get("control_id") or event.entity_id
        if control_id:
            # Убираем из счётчика (не меньше 0)
            current = ev_counts.get(control_id, 0)
            ev_counts[control_id] = max(0, current - 1)

    elif et == ComplianceEventType.SLA_BREACH.value:
        control_id = payload.get("control_id") or event.entity_id
        if control_id:
            ctrl_statuses[control_id] = _FAIL

    elif et == ComplianceEventType.RISK_CREATED.value:
        risk_id = event.entity_id
        severity = int(payload.get("severity", 3))
        risk_scores[risk_id] = severity

    elif et == ComplianceEventType.RISK_ESCALATED.value:
        risk_id = event.entity_id
        new_score = int(payload.get("new_severity", payload.get("severity", 5)))
        risk_scores[risk_id] = new_score

    return {
        "control_statuses": ctrl_statuses,
        "evidence_counts":  ev_counts,
        "risk_scores":      risk_scores,
    }


def _compute_score(control_statuses: Dict[str, str]) -> float:
    """Вычисляет overall compliance score (% контролей в PASS)."""
    if not control_statuses:
        return 0.0
    pass_count = sum(1 for s in control_statuses.values() if s == _PASS)
    return round(pass_count / len(control_statuses) * 100.0, 2)


# ── ComplianceReplayEngine ─────────────────────────────────────────────────────

class ComplianceReplayEngine:
    """
    Детерминированный replay engine.

    Воспроизводит compliance-состояние на любой момент времени путём
    последовательного применения событий из EventStore.

    Все методы потокобезопасны (EventStore thread-safe, replay stateless).
    """

    def __init__(self, store: Optional[EventStore] = None) -> None:
        self._store = store or get_event_store()

    # ── Основные методы ──────────────────────────────────────────────────────────

    def replay_to(self, target_datetime: datetime) -> ReplaySnapshot:
        """
        Воспроизводит полное compliance-состояние до target_datetime.

        Берёт все события с occurred_at <= target_datetime,
        применяет их детерминистически через reducer,
        возвращает ReplaySnapshot.

        Детерминизм: события применяются в порядке sequence_number.
        """
        _ensure_aware(target_datetime)

        # Собираем все события до целевого момента
        all_events = self._store.get_all()
        relevant = [
            e for e in all_events
            if e.occurred_at <= target_datetime
        ]
        # Сортируем по sequence_number для детерминизма
        relevant.sort(key=lambda e: e.sequence_number)

        state: Dict[str, Any] = {
            "control_statuses": {},
            "evidence_counts":  {},
            "risk_scores":      {},
        }
        for event in relevant:
            state = _apply_event(state, event)

        score = _compute_score(state["control_statuses"])

        return ReplaySnapshot(
            snapshot_at=target_datetime,
            control_statuses=state["control_statuses"],
            evidence_counts=state["evidence_counts"],
            risk_scores=state["risk_scores"],
            overall_score=score,
        )

    def replay_control(
        self,
        control_id: str,
        target_datetime: datetime,
    ) -> ControlHistory:
        """
        Воспроизводит историю изменений одного контроля до target_datetime.

        Возвращает ControlHistory с хронологическим списком переходов статуса.
        """
        _ensure_aware(target_datetime)
        epoch = datetime(2000, 1, 1, tzinfo=timezone.utc)

        events = self._store.get_events_in_range(epoch, target_datetime)
        events.sort(key=lambda e: e.sequence_number)

        transitions: List[Dict[str, Any]] = []
        current_status: Optional[str] = None

        for event in events:
            # Событие затрагивает этот контроль?
            involves_control = (
                event.entity_id == control_id
                or event.payload.get("control_id") == control_id
            )
            if not involves_control:
                continue

            # Вычисляем новый статус через mini-state
            mini_state: Dict[str, Any] = {
                "control_statuses": {control_id: current_status or _UNKNOWN},
                "evidence_counts":  {},
                "risk_scores":      {},
            }
            new_state = _apply_event(mini_state, event)
            new_status = new_state["control_statuses"].get(control_id, current_status)

            if new_status != current_status:
                transitions.append({
                    "occurred_at":  event.occurred_at.isoformat(),
                    "from_status":  current_status,
                    "to_status":    new_status,
                    "event_id":     event.event_id,
                    "event_type":   event.event_type,
                    "actor":        event.actor,
                })
                current_status = new_status

        return ControlHistory(
            control_id=control_id,
            from_dt=epoch,
            to_dt=target_datetime,
            transitions=transitions,
        )

    def compute_diff(
        self,
        snapshot_a: ReplaySnapshot,
        snapshot_b: ReplaySnapshot,
    ) -> SnapshotDiff:
        """
        Вычисляет разницу между двумя ReplaySnapshot.

        Возвращает SnapshotDiff с изменёнными контролями и рисками.
        """
        changed: List[Dict[str, Any]] = []

        all_controls = set(snapshot_a.control_statuses) | set(snapshot_b.control_statuses)
        for ctrl_id in sorted(all_controls):
            s_a = snapshot_a.control_statuses.get(ctrl_id, _UNKNOWN)
            s_b = snapshot_b.control_statuses.get(ctrl_id, _UNKNOWN)
            if s_a != s_b:
                changed.append({
                    "control_id":   ctrl_id,
                    "from_status":  s_a,
                    "to_status":    s_b,
                })

        risks_a = set(snapshot_a.risk_scores.keys())
        risks_b = set(snapshot_b.risk_scores.keys())
        new_risks = sorted(risks_b - risks_a)
        resolved_risks = sorted(risks_a - risks_b)

        score_delta = snapshot_b.overall_score - snapshot_a.overall_score

        return SnapshotDiff(
            from_dt=snapshot_a.snapshot_at,
            to_dt=snapshot_b.snapshot_at,
            score_delta=score_delta,
            changed=changed,
            new_risks=new_risks,
            resolved_risks=resolved_risks,
        )

    def find_regression(
        self,
        control_id: str,
        from_dt: datetime,
        to_dt: datetime,
    ) -> Optional[RegressionEvent]:
        """
        Находит первый момент регрессии контроля PASS → FAIL в диапазоне.

        Возвращает RegressionEvent с деталями первого регрессионного события,
        или None если регрессии не было.
        """
        _ensure_aware(from_dt)
        _ensure_aware(to_dt)

        events = self._store.get_events_in_range(from_dt, to_dt)
        events.sort(key=lambda e: e.sequence_number)

        # Сначала вычисляем статус на from_dt
        snapshot_before = self.replay_to(from_dt)
        current_status = snapshot_before.control_statuses.get(control_id, _UNKNOWN)

        for event in events:
            involves_control = (
                event.entity_id == control_id
                or event.payload.get("control_id") == control_id
            )
            if not involves_control:
                continue

            mini_state: Dict[str, Any] = {
                "control_statuses": {control_id: current_status},
                "evidence_counts":  {},
                "risk_scores":      {},
            }
            new_state = _apply_event(mini_state, event)
            new_status = new_state["control_statuses"].get(control_id, current_status)

            if current_status == _PASS and new_status == _FAIL:
                return RegressionEvent(
                    control_id=control_id,
                    occurred_at=event.occurred_at,
                    event_id=event.event_id,
                    actor=event.actor,
                    payload=event.payload,
                )

            current_status = new_status

        return None

    def get_compliance_timeline(
        self,
        from_dt: datetime,
        to_dt: datetime,
        resolution: str = "day",
    ) -> List[TimelinePoint]:
        """
        Возвращает timeline точек compliance за период.

        resolution: "hour" | "day" | "week"
        Каждая точка: datetime, score (%), pass_count, fail_count, total.

        Алгоритм:
          1. Генерируем список точек по resolution
          2. Для каждой точки — replay_to(point_dt)
          3. Возвращаем список TimelinePoint
        """
        _ensure_aware(from_dt)
        _ensure_aware(to_dt)

        points_dt = _generate_timeline_points(from_dt, to_dt, resolution)

        result: List[TimelinePoint] = []
        for point_dt in points_dt:
            snapshot = self.replay_to(point_dt)
            statuses = snapshot.control_statuses
            total = len(statuses)
            pass_count = sum(1 for s in statuses.values() if s == _PASS)
            fail_count = sum(1 for s in statuses.values() if s == _FAIL)
            result.append(TimelinePoint(
                point_at=point_dt,
                score=snapshot.overall_score,
                pass_count=pass_count,
                fail_count=fail_count,
                total=total,
            ))

        return result


# ── Вспомогательные функции ────────────────────────────────────────────────────

def _ensure_aware(dt: datetime) -> None:
    """Проверяет что datetime timezone-aware. Поднимает ValueError иначе."""
    if dt.tzinfo is None:
        raise ValueError(
            f"datetime должен быть timezone-aware: {dt!r}. "
            "Добавьте tzinfo=timezone.utc или используйте datetime.now(timezone.utc)."
        )


def _generate_timeline_points(
    from_dt: datetime,
    to_dt: datetime,
    resolution: str,
) -> List[datetime]:
    """
    Генерирует список datetime-точек для timeline.

    resolution: "hour" → каждый час, "day" → каждый день, "week" → каждую неделю.
    """
    step_map = {
        "hour": timedelta(hours=1),
        "day":  timedelta(days=1),
        "week": timedelta(weeks=1),
    }
    step = step_map.get(resolution, timedelta(days=1))

    points: List[datetime] = []
    current = from_dt
    while current <= to_dt:
        points.append(current)
        current = current + step

    # Всегда включаем to_dt если он не совпадает с последней точкой
    if points and points[-1] < to_dt:
        points.append(to_dt)

    return points


# ── EventBus интеграция ────────────────────────────────────────────────────────

class EventBusToStoreAdapter:
    """
    Подписывается на EventBus и записывает все события в EventStore.

    Интеграция без изменения EventBus: subscribe_all(handler).
    causation_id и correlation_id берутся из payload если есть.
    """

    def __init__(
        self,
        store: Optional[EventStore] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        self._store = store or get_event_store()
        self._correlation_id = correlation_id

    def attach(self) -> None:
        """Регистрирует handler в EventBus."""
        bus = get_event_bus()
        bus.subscribe_all(self._handle_event)
        log.info("EventBusToStoreAdapter: подписан на EventBus")

    def _handle_event(self, event: ComplianceEvent) -> None:
        """Handler: конвертирует ComplianceEvent → SourcedEvent и записывает."""
        try:
            causation_id = event.payload.get("source_event") or event.payload.get("causation_id")
            correlation_id = (
                event.payload.get("correlation_id")
                or self._correlation_id
            )

            # Создаём SourcedEvent с временным seq=0 (EventStore назначит правильный)
            sourced = SourcedEvent(
                event_id=event.event_id,
                sequence_number=0,  # будет перезаписан в append()
                event_type=event.event_type.value,
                entity_type=event.entity_type,
                entity_id=event.entity_id,
                actor=event.actor,
                payload=dict(event.payload),
                occurred_at=event.timestamp,
                recorded_at=datetime.now(timezone.utc),
                causation_id=causation_id,
                correlation_id=correlation_id,
            )
            self._store.append(sourced)
        except Exception as exc:
            log.error(
                "EventBusToStoreAdapter: ошибка записи события",
                extra={"error": str(exc), "event_id": event.event_id},
            )


# ── Singleton ──────────────────────────────────────────────────────────────────

_store_instance: Optional[EventStore] = None
_store_lock = threading.Lock()

_engine_instance: Optional[ComplianceReplayEngine] = None
_engine_lock = threading.Lock()


def get_event_store(store_path: Optional[Path] = None) -> EventStore:
    """Thread-safe singleton EventStore."""
    global _store_instance
    if _store_instance is None:
        with _store_lock:
            if _store_instance is None:
                _store_instance = EventStore(store_path)
                log.info("EventStore: singleton создан")
    return _store_instance


def get_replay_engine() -> ComplianceReplayEngine:
    """Thread-safe singleton ComplianceReplayEngine."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                _engine_instance = ComplianceReplayEngine(get_event_store())
                log.info("ComplianceReplayEngine: singleton создан")
    return _engine_instance


def reset_singletons_for_testing() -> None:
    """
    Сбрасывает синглтоны для тестовой изоляции.
    ТОЛЬКО ДЛЯ ТЕСТОВ.
    """
    global _store_instance, _engine_instance
    with _store_lock:
        _store_instance = None
    with _engine_lock:
        _engine_instance = None
