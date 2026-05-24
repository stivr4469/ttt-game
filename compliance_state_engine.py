"""
compliance_state_engine.py — Единственный авторитативный источник compliance-состояния.

Архитектура:
  ComplianceStateEngine  — singleton, единственный авторитет compliance-state
  ControlState           — полный контекст одного контроля
  CompliancePosture      — общая картина compliance
  FailExplanation        — объяснение FAIL с dependency chain

Принципы:
  1. Только deterministic logic (не AI) принимает решения о статусе
  2. AI (ai_advisor.py) — только советует через отдельный endpoint
  3. Thread-safe: RLock защищает весь внутренний кэш
  4. Graceful degradation: при недоступности DB работает через JSON-файлы
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from compliance_engine import (
    ComplianceEngine,
    ControlVerdict,
    VerdictStatus,
    get_compliance_engine,
    _CONTROL_WEIGHTS,
    _REQUIRED_EVIDENCE_TYPES,
)
from compliance_graph import ComplianceGraph
from graph_builder import get_compliance_graph
from event_bus import (
    ComplianceEvent,
    ComplianceEventType,
    get_event_bus,
)
from log_config import get_logger

log = get_logger(__name__)

# Корень проекта
_ROOT = Path(__file__).parent

# ── Dataclasses ────────────────────────────────────────────────────────────────

@dataclass
class ControlState:
    """
    Полный контекст состояния одного контроля.

    Единственный авторитативный объект — заполняется только
    ComplianceStateEngine через deterministic logic.
    """
    control_id: str
    status: str                        # "PASS" | "FAIL" | "NEEDS_REVIEW" | "UNKNOWN"
    confidence: float                  # 0.0–1.0
    evidence_count: int
    evidence_ids: List[str]
    risk_ids: List[str]
    affected_frameworks: List[str]     # из ontology (iso27001, nist, cis)
    last_evaluated: datetime
    why_message: str                   # причина статуса (why_fail / why_pass)
    missing_evidence: List[str]        # пустой при PASS
    weight: float                      # вес для scoring

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "status": self.status,
            "confidence": self.confidence,
            "evidence_count": self.evidence_count,
            "evidence_ids": self.evidence_ids,
            "risk_ids": self.risk_ids,
            "affected_frameworks": self.affected_frameworks,
            "last_evaluated": self.last_evaluated.isoformat(),
            "why_message": self.why_message,
            "missing_evidence": self.missing_evidence,
            "weight": self.weight,
        }


@dataclass
class CompliancePosture:
    """
    Общая картина compliance по всем контролям.

    Вычисляется детерминированно из актуальных ControlState.
    """
    score: float                       # 0.0–100.0 (unweighted average)
    weighted_score: float              # 0.0–100.0 (взвешенный)
    breakdown: Dict[str, Dict[str, Any]]  # {категория: {pass/fail/needs_review/total}}
    critical_fails: List[str]          # control_ids с weight >= 3.0 и статусом FAIL
    total_evidence_count: int
    total_controls: int
    last_updated: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "weighted_score": self.weighted_score,
            "breakdown": self.breakdown,
            "critical_fails": self.critical_fails,
            "total_evidence_count": self.total_evidence_count,
            "total_controls": self.total_controls,
            "last_updated": self.last_updated.isoformat(),
        }


@dataclass
class FailExplanation:
    """
    Полное объяснение FAIL-статуса контроля с dependency chain.
    """
    control_id: str
    status: str
    primary_reason: str
    dependency_chain: List[str]        # control_ids образующих цепочку зависимостей
    affected_controls: List[str]       # смежные контроли из графа
    risk_propagation: List[Dict[str, Any]]  # риски затронутые FAIL
    remediation_sla: int               # часов SLA из онтологии
    triggering_events: List[Dict[str, Any]]  # последние события из event_bus

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "status": self.status,
            "primary_reason": self.primary_reason,
            "dependency_chain": self.dependency_chain,
            "affected_controls": self.affected_controls,
            "risk_propagation": self.risk_propagation,
            "remediation_sla": self.remediation_sla,
            "triggering_events": self.triggering_events,
        }


# ── Вспомогательные функции ────────────────────────────────────────────────────

def _load_json(path: Path, default: Any = None) -> Any:
    """Загружает JSON-файл или возвращает default при ошибке."""
    if not path.exists():
        log.warning("Файл не найден, пропускаю: %s", path)
        return default if default is not None else {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        log.error("Ошибка загрузки %s: %s", path, exc)
        return default if default is not None else {}


def _utcnow() -> datetime:
    """Текущее время UTC."""
    return datetime.now(timezone.utc)


def _extract_category(control_id: str) -> str:
    """
    Извлекает категорию из control_id.
    CC6.1 → "CC6", A1.1 → "A1", PI1.1 → "PI1", C1.1 → "C1", P1.1 → "P1"
    """
    parts = control_id.split(".")
    return parts[0] if parts else control_id


def _get_control_weight(control_id: str) -> float:
    """Возвращает вес контроля (из compliance_engine._CONTROL_WEIGHTS)."""
    return _CONTROL_WEIGHTS.get(control_id, 1.0)


def _load_evidence_for_control(control_id: str) -> List[Dict[str, Any]]:
    """
    Загружает evidence для контроля из JSON-файлов.

    Читает controls_map.json и data/evidences.json (если доступен).
    Fallback: возвращает пустой список.
    """
    controls_map = _load_json(_ROOT / "controls_map.json", default={})
    evidence_ids = controls_map.get(control_id, [])

    # Нормализуем к списку
    if isinstance(evidence_ids, str):
        evidence_ids = [evidence_ids] if evidence_ids else []

    if not evidence_ids:
        return []

    # Пытаемся загрузить метаданные evidence из data/evidences.json
    evidence_data = _load_json(_ROOT / "data" / "evidences.json", default=[])
    evidence_index: Dict[str, Dict] = {}
    if isinstance(evidence_data, list):
        for ev in evidence_data:
            ev_id = ev.get("id") or ev.get("evidence_id")
            if ev_id:
                evidence_index[str(ev_id)] = ev

    result: List[Dict[str, Any]] = []
    for ev_id in evidence_ids:
        ev_id_str = str(ev_id)
        if ev_id_str in evidence_index:
            result.append(evidence_index[ev_id_str])
        else:
            # Создаём минимальный placeholder из controls_map
            result.append({
                "id": ev_id_str,
                "control_id": control_id,
                "status": "PASS",  # присутствие в controls_map = собрано успешно
                "evidence_type": "",
                "title": f"Evidence {ev_id_str}",
                "source": "controls_map",
            })

    return result


def _load_risk_ids_for_control(control_id: str) -> List[str]:
    """Загружает список risk_id, связанных с контролем."""
    risk_register = _load_json(_ROOT / "risk_register.json", default=[])
    return [
        r["id"]
        for r in risk_register
        if isinstance(r, dict) and r.get("control_id") == control_id and r.get("id")
    ]


def _load_affected_frameworks(control_id: str) -> List[str]:
    """
    Загружает фреймворки для контроля из онтологии.
    Возвращает список строк типа ['iso27001:A.9.4.2', 'nist:IA-2']
    """
    try:
        from compliance_ontology import get_ontology_engine
        engine = get_ontology_engine()
        ctrl = engine.get_control(control_id)
        if not ctrl:
            return ["soc2"]
        frameworks: List[str] = ["soc2"]
        for iso in ctrl.iso27001:
            frameworks.append(f"iso27001:{iso}")
        for nist in ctrl.nist:
            frameworks.append(f"nist:{nist}")
        for cis in ctrl.cis:
            frameworks.append(f"cis:{cis}")
        return frameworks
    except Exception as exc:
        log.debug("Онтология недоступна для %s: %s", control_id, exc)
        return ["soc2"]


def _load_remediation_sla(control_id: str) -> int:
    """Загружает SLA устранения из онтологии (в часах)."""
    try:
        from compliance_ontology import get_ontology_engine
        engine = get_ontology_engine()
        return engine.get_remediation_sla(control_id)
    except Exception:
        return 168  # 1 неделя по умолчанию


def _get_all_known_control_ids() -> List[str]:
    """Возвращает список всех известных control_id из controls_map + risk_register."""
    controls_map = _load_json(_ROOT / "controls_map.json", default={})
    control_ids: set = set(controls_map.keys())

    risk_register = _load_json(_ROOT / "risk_register.json", default=[])
    for r in risk_register:
        if isinstance(r, dict) and r.get("control_id"):
            control_ids.add(r["control_id"])

    # Добавляем из _REQUIRED_EVIDENCE_TYPES (canonical list)
    control_ids.update(_REQUIRED_EVIDENCE_TYPES.keys())

    return sorted(control_ids)


# ── ComplianceStateEngine ──────────────────────────────────────────────────────

class ComplianceStateEngine:
    """
    Единственный авторитет compliance-state в системе.

    Отвечает за:
      - хранение актуального состояния всех контролей
      - детерминированный пересчёт через compliance_engine.py
      - публикацию событий через event_bus.py при изменении статуса
      - предоставление объяснений FAIL через граф зависимостей
      - сериализацию/восстановление snapshot для time-machine

    Thread-safe: RLock защищает _cache, _posture_cache.
    """

    def __init__(
        self,
        engine: Optional[ComplianceEngine] = None,
    ) -> None:
        self._engine: ComplianceEngine = engine or get_compliance_engine()
        # Кэш: control_id → ControlState
        self._cache: Dict[str, ControlState] = {}
        # Кэш общей посчуры (инвалидируется при recalculate)
        self._posture_cache: Optional[CompliancePosture] = None
        # RLock для вложенных вызовов из одного потока
        self._lock = threading.RLock()
        log.info("ComplianceStateEngine инициализирован")

    # ── Основные методы получения состояния ───────────────────────────────────

    def get_control_state(self, control_id: str) -> ControlState:
        """
        Возвращает полный контекст контроля.

        Если состояние не вычислено — вычисляет lazily.
        Если control_id неизвестен — возвращает UNKNOWN-состояние.

        Double-checked locking: проверяем кэш до и после вычисления,
        чтобы избежать race condition при конкурентных вызовах.
        """
        # Быстрая проверка под lock
        with self._lock:
            if control_id in self._cache:
                return self._cache[control_id]

        # Вычисляем вне lock чтобы не блокировать других читателей
        state = self._compute_control_state(control_id)

        # Записываем под lock (second-check: другой поток мог записать пока мы вычисляли)
        with self._lock:
            if control_id not in self._cache:
                self._cache[control_id] = state
                self._posture_cache = None  # инвалидируем posture
            return self._cache[control_id]

    def get_full_compliance_posture(self) -> CompliancePosture:
        """
        Возвращает общую compliance posture.

        Использует кэш; инвалидируется при каждом recalculate.
        """
        with self._lock:
            if self._posture_cache is not None:
                return self._posture_cache

        # Вычисляем вне lock
        posture = self._compute_posture()

        with self._lock:
            self._posture_cache = posture

        return posture

    def explain_control_fail(self, control_id: str) -> FailExplanation:
        """
        Объяснение FAIL-статуса с dependency chain и propagation.

        Работает для любого статуса (not только FAIL).
        """
        state = self.get_control_state(control_id)
        graph = self._get_graph()

        # Dependency chain: BFS по depends_on рёбрам
        dependency_chain = self._build_dependency_chain(control_id, graph)

        # Affected controls: контроли которые required_by этого
        affected = self._get_affected_controls(control_id, graph)

        # Risk propagation через граф
        risk_propagation = self._get_risk_propagation(control_id, graph)

        # SLA из онтологии
        sla = _load_remediation_sla(control_id)

        # События из event_bus
        events = self._get_triggering_events(control_id)

        return FailExplanation(
            control_id=control_id,
            status=state.status,
            primary_reason=state.why_message,
            dependency_chain=dependency_chain,
            affected_controls=affected,
            risk_propagation=risk_propagation,
            remediation_sla=sla,
            triggering_events=events,
        )

    def recalculate(self, control_id: Optional[str] = None) -> None:
        """
        Принудительный пересчёт состояния.

        Args:
            control_id: если задан — пересчитывает только этот контроль,
                        иначе пересчитывает все известные контроли.

        Публикует CONTROL_STATUS_CHANGED если статус изменился.
        """
        if control_id is not None:
            self._recalculate_one(control_id)
        else:
            self._recalculate_all()

        # Инвалидируем posture кэш
        with self._lock:
            self._posture_cache = None

    def get_state_snapshot(self) -> Dict[str, Any]:
        """
        Полный compliance state как JSON-serializable dict.

        Используется time-machine и replay engine.
        """
        with self._lock:
            cache_copy = dict(self._cache)

        snapshot: Dict[str, Any] = {
            "version": "1.0",
            "timestamp": _utcnow().isoformat(),
            "controls": {
                ctrl_id: state.to_dict()
                for ctrl_id, state in cache_copy.items()
            },
        }

        # Добавляем posture если вычислена
        try:
            posture = self.get_full_compliance_posture()
            snapshot["posture"] = posture.to_dict()
        except Exception as exc:
            log.warning("Не удалось добавить posture в snapshot: %s", exc)
            snapshot["posture"] = None

        return snapshot

    def apply_snapshot(self, snapshot: Dict[str, Any]) -> None:
        """
        Восстановить state из snapshot (для replay engine).

        Заменяет текущий кэш состоянием из snapshot.
        Публикует события для всех изменившихся контролей.
        """
        version = snapshot.get("version", "1.0")
        log.info("Восстановление snapshot версии %s", version)

        controls_data = snapshot.get("controls", {})
        new_cache: Dict[str, ControlState] = {}

        for ctrl_id, ctrl_dict in controls_data.items():
            try:
                state = self._dict_to_control_state(ctrl_dict)
                new_cache[ctrl_id] = state
            except Exception as exc:
                log.warning("Пропуск контроля %s при восстановлении: %s", ctrl_id, exc)

        with self._lock:
            old_cache = dict(self._cache)
            self._cache = new_cache
            self._posture_cache = None

        # Публикуем события для изменившихся контролей
        event_bus = get_event_bus()
        for ctrl_id, new_state in new_cache.items():
            old_state = old_cache.get(ctrl_id)
            if old_state is None or old_state.status != new_state.status:
                event_bus.publish(ComplianceEvent.create(
                    event_type=ComplianceEventType.CONTROL_STATUS_CHANGED,
                    entity_type="control",
                    entity_id=ctrl_id,
                    actor="system:replay",
                    payload={
                        "old_status": old_state.status if old_state else "UNKNOWN",
                        "new_status": new_state.status,
                        "snapshot_restore": True,
                    },
                    severity="info",
                ))

        log.info(
            "Snapshot восстановлен: %d контролей загружено",
            len(new_cache),
        )

    # ── Внутренние методы вычисления ──────────────────────────────────────────

    def _compute_control_state(self, control_id: str) -> ControlState:
        """
        Детерминированное вычисление состояния одного контроля.
        НЕ вызывает AI.
        """
        # Загружаем evidence
        evidence_list = _load_evidence_for_control(control_id)
        evidence_ids = [
            str(ev.get("id", ""))
            for ev in evidence_list
            if ev.get("id")
        ]

        # Запускаем детерминированный engine
        verdict: ControlVerdict = self._engine.evaluate_control(
            control_id=control_id,
            evidence_list=evidence_list,
        )

        # Загружаем вспомогательные данные
        risk_ids = _load_risk_ids_for_control(control_id)
        frameworks = _load_affected_frameworks(control_id)
        weight = _get_control_weight(control_id)

        # Формируем сообщение о причине статуса
        why_message = self._format_why_message(verdict)

        return ControlState(
            control_id=control_id,
            status=verdict.status.value,
            confidence=verdict.confidence,
            evidence_count=len(evidence_list),
            evidence_ids=evidence_ids,
            risk_ids=risk_ids,
            affected_frameworks=frameworks,
            last_evaluated=_utcnow(),
            why_message=why_message,
            missing_evidence=verdict.missing_evidence,
            weight=weight,
        )

    def _compute_posture(self) -> CompliancePosture:
        """Вычисляет общую compliance posture по всем контролям."""
        all_control_ids = _get_all_known_control_ids()

        # Обеспечиваем что все контроли вычислены
        states: List[ControlState] = []
        for ctrl_id in all_control_ids:
            try:
                state = self.get_control_state(ctrl_id)
                states.append(state)
            except Exception as exc:
                log.warning("Не удалось получить state для %s: %s", ctrl_id, exc)

        if not states:
            return CompliancePosture(
                score=0.0,
                weighted_score=0.0,
                breakdown={},
                critical_fails=[],
                total_evidence_count=0,
                total_controls=0,
                last_updated=_utcnow(),
            )

        # Подсчёт breakdown по категориям
        breakdown: Dict[str, Dict[str, Any]] = {}
        status_scores = {"PASS": 1.0, "NEEDS_REVIEW": 0.5, "FAIL": 0.0, "UNKNOWN": 0.0}

        total_weight = 0.0
        weighted_sum = 0.0
        total_score_sum = 0.0
        critical_fails: List[str] = []
        total_evidence = 0

        for state in states:
            category = _extract_category(state.control_id)
            if category not in breakdown:
                breakdown[category] = {
                    "pass": 0, "fail": 0, "needs_review": 0,
                    "unknown": 0, "total": 0,
                }

            status_key = state.status.lower() if state.status.lower() in (
                "pass", "fail", "needs_review", "unknown"
            ) else "unknown"
            breakdown[category][status_key] = breakdown[category].get(status_key, 0) + 1
            breakdown[category]["total"] += 1

            numeric_score = status_scores.get(state.status, 0.0)
            total_score_sum += numeric_score

            w = state.weight
            weighted_sum += w * numeric_score
            total_weight += w
            total_evidence += state.evidence_count

            # Critical fails: FAIL с высоким весом
            if state.status == "FAIL" and state.weight >= 3.0:
                critical_fails.append(state.control_id)

        n = len(states)
        score = round((total_score_sum / n) * 100.0, 1) if n > 0 else 0.0
        weighted_score = round(
            (weighted_sum / total_weight) * 100.0, 1
        ) if total_weight > 0 else 0.0

        return CompliancePosture(
            score=score,
            weighted_score=weighted_score,
            breakdown=breakdown,
            critical_fails=sorted(critical_fails),
            total_evidence_count=total_evidence,
            total_controls=n,
            last_updated=_utcnow(),
        )

    def _recalculate_one(self, control_id: str) -> None:
        """Пересчитывает один контроль и публикует событие если статус изменился."""
        with self._lock:
            old_state = self._cache.get(control_id)

        new_state = self._compute_control_state(control_id)

        with self._lock:
            self._cache[control_id] = new_state
            self._posture_cache = None

        # Публикуем событие при изменении статуса
        if old_state is None or old_state.status != new_state.status:
            severity = "critical" if new_state.status == "FAIL" else "info"
            get_event_bus().publish(ComplianceEvent.create(
                event_type=ComplianceEventType.CONTROL_STATUS_CHANGED,
                entity_type="control",
                entity_id=control_id,
                actor="system:state_engine",
                payload={
                    "old_status": old_state.status if old_state else "UNKNOWN",
                    "new_status": new_state.status,
                    "confidence": new_state.confidence,
                    "missing_evidence": new_state.missing_evidence,
                },
                severity=severity,
            ))
            log.info(
                "Контроль %s: статус изменён %s → %s",
                control_id,
                old_state.status if old_state else "UNKNOWN",
                new_state.status,
            )

    def _recalculate_all(self) -> None:
        """Пересчитывает все известные контроли."""
        all_control_ids = _get_all_known_control_ids()
        log.info("Пересчёт всех контролей: %d контролей", len(all_control_ids))

        for ctrl_id in all_control_ids:
            try:
                self._recalculate_one(ctrl_id)
            except Exception as exc:
                log.error("Ошибка пересчёта контроля %s: %s", ctrl_id, exc)

        log.info("Пересчёт завершён: %d контролей обновлено", len(all_control_ids))

    # ── Граф и dependency chain ────────────────────────────────────────────────

    def _get_graph(self) -> ComplianceGraph:
        """Получает compliance граф (с graceful fallback)."""
        try:
            return get_compliance_graph()
        except Exception as exc:
            log.warning("Граф недоступен, использую пустой: %s", exc)
            from compliance_graph import ComplianceGraph as CG
            return CG()

    def _build_dependency_chain(
        self, control_id: str, graph: ComplianceGraph
    ) -> List[str]:
        """
        Строит цепочку зависимостей контроля (BFS по depends_on рёбрам).

        Возвращает список control_id от корня до данного контроля.
        """
        chain: List[str] = []
        visited: set = set()
        queue = [control_id]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            # Зависимости: контроли на которые ОПИРАЕТСЯ current
            deps = graph.get_neighbors(current, edge_type="depends_on")
            for dep in deps:
                if dep.node_id not in visited:
                    chain.append(dep.node_id)
                    queue.append(dep.node_id)

        return chain

    def _get_affected_controls(
        self, control_id: str, graph: ComplianceGraph
    ) -> List[str]:
        """
        Возвращает контроли которые ЗАВИСЯТ от данного (required_by).
        """
        try:
            required_by = graph.get_reverse_neighbors(
                control_id, edge_type="depends_on"
            )
            return [n.node_id for n in required_by]
        except Exception:
            return []

    def _get_risk_propagation(
        self, control_id: str, graph: ComplianceGraph
    ) -> List[Dict[str, Any]]:
        """Возвращает риски связанные с контролем."""
        try:
            risk_nodes = graph.get_neighbors(control_id, edge_type="has_risk")
            return [
                {
                    "risk_id": n.node_id,
                    "title": n.data.get("title", ""),
                    "score": n.data.get("score", 0),
                    "status": n.data.get("status", "open"),
                }
                for n in risk_nodes
            ]
        except Exception:
            return []

    def _get_triggering_events(self, control_id: str) -> List[Dict[str, Any]]:
        """
        Получает последние события для контроля из event_bus истории.

        Использует встроенный entity_id фильтр EventBus.get_history()
        для эффективного поиска.
        """
        try:
            bus = get_event_bus()
            # Используем встроенный фильтр — не загружаем всю историю
            events = bus.get_history(entity_id=control_id, limit=10)
            return [ev.to_dict() for ev in events]
        except Exception as exc:
            log.debug("История событий недоступна для %s: %s", control_id, exc)
            return []

    # ── Вспомогательные методы ─────────────────────────────────────────────────

    @staticmethod
    def _format_why_message(verdict: ControlVerdict) -> str:
        """Формирует человекочитаемое сообщение о причине статуса."""
        if verdict.status == VerdictStatus.FAIL:
            reasons = "; ".join(verdict.reasons[:3])
            return f"FAIL: {reasons}" if reasons else "FAIL: обнаружены FAIL-evidence"
        elif verdict.status == VerdictStatus.PASS:
            return "; ".join(verdict.reasons[:2]) or "PASS: все требования выполнены"
        else:
            missing = ", ".join(verdict.missing_evidence[:5])
            if missing:
                return f"NEEDS_REVIEW: отсутствуют типы evidence: {missing}"
            return "NEEDS_REVIEW: недостаточно evidence для оценки"

    @staticmethod
    def _dict_to_control_state(d: Dict[str, Any]) -> ControlState:
        """Десериализует ControlState из словаря."""
        ts = d.get("last_evaluated")
        if isinstance(ts, str):
            last_evaluated = datetime.fromisoformat(ts)
        elif isinstance(ts, datetime):
            last_evaluated = ts
        else:
            last_evaluated = _utcnow()

        return ControlState(
            control_id=d["control_id"],
            status=d.get("status", "UNKNOWN"),
            confidence=float(d.get("confidence", 0.0)),
            evidence_count=int(d.get("evidence_count", 0)),
            evidence_ids=list(d.get("evidence_ids", [])),
            risk_ids=list(d.get("risk_ids", [])),
            affected_frameworks=list(d.get("affected_frameworks", ["soc2"])),
            last_evaluated=last_evaluated,
            why_message=d.get("why_message", ""),
            missing_evidence=list(d.get("missing_evidence", [])),
            weight=float(d.get("weight", 1.0)),
        )


# ── Thread-safe singleton ──────────────────────────────────────────────────────

_state_engine_instance: Optional[ComplianceStateEngine] = None
_singleton_lock = threading.Lock()


def get_state_engine() -> ComplianceStateEngine:
    """
    Получить singleton ComplianceStateEngine (thread-safe ленивая инициализация).
    """
    global _state_engine_instance
    if _state_engine_instance is None:
        with _singleton_lock:
            if _state_engine_instance is None:
                _state_engine_instance = ComplianceStateEngine()
    return _state_engine_instance


def reset_state_engine() -> None:
    """
    Сброс singleton для тестов.
    НЕ использовать в production.
    """
    global _state_engine_instance
    with _singleton_lock:
        _state_engine_instance = None
