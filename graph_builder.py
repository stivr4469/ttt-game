"""
graph_builder.py — Строит ComplianceGraph из существующих JSON-данных.

Читает:
  - controls_map.json      : control_id → evidence_id
  - risk_register.json     : список рисков (RISK-XXX с control_id)
  - data/vendors.json      : список вендоров (VND-XXX)
  - data/ai_decisions.json : решения AI (опционально)

Строит узлы и рёбра:
  Control → Evidence  (has_evidence)
  Control → Risk      (has_risk)
  Risk    → Vendor    (owned_by)  — через category/control_id cross-reference
  Control → Control   (depends_on) — из ontology requires

Кэш держится в памяти, rebuild по требованию через rebuild().
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Optional

from compliance_graph import ComplianceGraph, GraphEdge, GraphNode
from log_config import get_logger

log = get_logger(__name__)

# Корень проекта
_ROOT = Path(__file__).parent


# ── Вспомогательные функции загрузки файлов ───────────────────────────────────

def _load_json(path: Path, default: Any = None) -> Any:
    """
    Загружает JSON-файл или возвращает default при ошибке.
    Логирует предупреждение если файл не найден.
    """
    if not path.exists():
        log.warning("Файл не найден, пропускаю: %s", path)
        return default if default is not None else {}
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        log.error("Ошибка загрузки %s: %s", path, exc)
        return default if default is not None else {}


# ── Основной Builder ──────────────────────────────────────────────────────────

class GraphBuilder:
    """
    Строит ComplianceGraph из JSON-файлов проекта.

    Кэш держит последний построенный граф.
    Вызов rebuild() сбрасывает кэш и пересобирает граф.

    Thread-safe: использует threading.Lock для защиты _cache.
    """

    def __init__(self, root: Path = _ROOT) -> None:
        self._root = root
        self._cache: Optional[ComplianceGraph] = None
        self._lock = threading.Lock()

    # ── Публичный API ──────────────────────────────────────────────────────

    def build_from_state(self) -> ComplianceGraph:
        """
        Вернуть актуальный граф из кэша или построить заново.

        Кэширует результат в памяти. Для принудительного пересчёта
        используйте rebuild().
        """
        if self._cache is not None:
            return self._cache

        with self._lock:
            # Double-checked locking: проверяем ещё раз под блокировкой
            if self._cache is None:
                self._cache = self._build()
        return self._cache

    def rebuild(self) -> ComplianceGraph:
        """Сбросить кэш и пересобрать граф из актуальных данных."""
        with self._lock:
            self._cache = self._build()
        return self._cache

    # ── Внутренняя сборка графа ────────────────────────────────────────────

    def _build(self) -> ComplianceGraph:
        """
        Полная сборка графа из JSON-источников.

        Шаги:
          1. Загрузка данных из файлов
          2. Добавление узлов всех типов
          3. Связывание рёбрами
          4. Обогащение данными онтологии (depends_on)
        """
        log.info("GraphBuilder: начало построения compliance-графа")
        graph = ComplianceGraph()

        # Загружаем все источники данных
        controls_map: dict[str, Any] = _load_json(
            self._root / "controls_map.json", default={}
        )
        risk_register: list[dict[str, Any]] = _load_json(
            self._root / "risk_register.json", default=[]
        )
        vendors: list[dict[str, Any]] = _load_json(
            self._root / "data" / "vendors.json", default=[]
        )
        ai_decisions: list[dict[str, Any]] = _load_json(
            self._root / "data" / "ai_decisions.json", default=[]
        )

        # controls_map.json хранит {control_id: evidence_id (str или list)}
        # Нормализуем к списку evidence_ids
        ctrl_evidence_map: dict[str, list[str]] = {}
        for ctrl_id, evidence_val in controls_map.items():
            if isinstance(evidence_val, list):
                ctrl_evidence_map[ctrl_id] = evidence_val
            elif evidence_val:
                ctrl_evidence_map[ctrl_id] = [str(evidence_val)]
            else:
                ctrl_evidence_map[ctrl_id] = []

        # Получаем список уникальных control_id
        all_control_ids: set[str] = set(ctrl_evidence_map.keys())
        # Добавляем контроли из risk_register
        for risk in risk_register:
            if risk.get("control_id"):
                all_control_ids.add(risk["control_id"])

        # ── 1. Добавляем узлы Control ──────────────────────────────────────
        self._add_control_nodes(graph, all_control_ids)

        # ── 2. Добавляем узлы Evidence и рёбра control → evidence ─────────
        self._add_evidence_nodes(graph, ctrl_evidence_map)

        # ── 3. Добавляем узлы Risk и рёбра control → risk ─────────────────
        self._add_risk_nodes(graph, risk_register)

        # ── 4. Добавляем узлы Vendor и рёбра risk → vendor ────────────────
        self._add_vendor_nodes(graph, vendors, risk_register)

        # ── 5. Добавляем рёбра control → control (depends_on) из онтологии
        self._add_dependency_edges(graph)

        # ── 6. Опциональные узлы из AI decisions ──────────────────────────
        if ai_decisions:
            self._add_ai_decision_nodes(graph, ai_decisions)

        summary = graph.get_summary()
        log.info(
            "GraphBuilder: граф построен — узлов: %d, рёбер: %d, компонент: %d",
            summary["node_count"],
            summary["edge_count"],
            summary["connected_components"],
        )
        return graph

    # ── Добавление Control-узлов ───────────────────────────────────────────

    def _add_control_nodes(
        self,
        graph: ComplianceGraph,
        control_ids: set[str],
    ) -> None:
        """Добавляет узлы типа 'control' для всех известных control_id."""
        # Пытаемся обогатить данными из онтологии
        ontology_map: dict[str, Any] = self._load_ontology()

        for ctrl_id in sorted(control_ids):
            ctrl_data: dict[str, Any] = {"control_id": ctrl_id}
            ctrl_meta: dict[str, Any] = {"frameworks": ["soc2"]}

            ontology_entry = ontology_map.get(ctrl_id)
            if ontology_entry:
                ctrl_data.update({
                    "title": ontology_entry.get("title", ctrl_id),
                    "category": ontology_entry.get("category", ""),
                    "risk_weight": ontology_entry.get("risk_weight", 0.5),
                    "sla_hours": ontology_entry.get("sla_hours", 168),
                    "auto_remediable": ontology_entry.get("auto_remediable", False),
                    "owner_role": ontology_entry.get("owner_role", "security_team"),
                })
                ctrl_meta["ontology_loaded"] = True

            graph.add_node(GraphNode(
                node_id=ctrl_id,
                node_type="control",
                data=ctrl_data,
                metadata=ctrl_meta,
            ))

        log.debug("GraphBuilder: добавлено %d control-узлов", len(control_ids))

    # ── Добавление Evidence-узлов ──────────────────────────────────────────

    def _add_evidence_nodes(
        self,
        graph: ComplianceGraph,
        ctrl_evidence_map: dict[str, list[str]],
    ) -> None:
        """
        Добавляет узлы типа 'evidence' и рёбра control → evidence (has_evidence).

        controls_map.json хранит evidence_id (UUID строки).
        Один контроль может иметь несколько evidence_id.
        """
        evidence_count = 0
        edge_count = 0

        for ctrl_id, evidence_ids in ctrl_evidence_map.items():
            for ev_id in evidence_ids:
                if not ev_id:
                    continue
                # Добавляем узел evidence если ещё нет
                if graph.get_node(ev_id) is None:
                    graph.add_node(GraphNode(
                        node_id=ev_id,
                        node_type="evidence",
                        data={"evidence_id": ev_id, "control_id": ctrl_id},
                        metadata={"source": "controls_map"},
                    ))
                    evidence_count += 1

                # Ребро control → evidence
                edge_added = graph.add_edge_safe(GraphEdge(
                    source_id=ctrl_id,
                    target_id=ev_id,
                    edge_type="has_evidence",
                    weight=1.0,
                ))
                if edge_added:
                    edge_count += 1

        log.debug(
            "GraphBuilder: добавлено %d evidence-узлов, %d рёбер has_evidence",
            evidence_count, edge_count,
        )

    # ── Добавление Risk-узлов ──────────────────────────────────────────────

    def _add_risk_nodes(
        self,
        graph: ComplianceGraph,
        risk_register: list[dict[str, Any]],
    ) -> None:
        """
        Добавляет узлы типа 'risk' и рёбра control → risk (has_risk).

        risk_register.json: список {id, control_id, title, score, ...}
        """
        risk_count = 0
        edge_count = 0

        for risk in risk_register:
            risk_id = risk.get("id")
            if not risk_id:
                continue

            # Узел риска
            if graph.get_node(risk_id) is None:
                graph.add_node(GraphNode(
                    node_id=risk_id,
                    node_type="risk",
                    data={
                        "risk_id": risk_id,
                        "title": risk.get("title", ""),
                        "description": risk.get("description", ""),
                        "score": risk.get("risk_score", risk.get("score", 0)),
                        "likelihood": risk.get("likelihood", 3),
                        "impact": risk.get("impact", 3),
                        "status": risk.get("status", "open"),
                        "category": risk.get("category", ""),
                        "treatment": risk.get("treatment", "mitigate"),
                        "owner": risk.get("owner", ""),
                    },
                    metadata={
                        "source": risk.get("source", "manual"),
                        "created_at": risk.get("created_at", ""),
                        "target_date": risk.get("target_date", ""),
                    },
                ))
                risk_count += 1

            # Ребро control → risk (has_risk)
            ctrl_id = risk.get("control_id")
            if ctrl_id and graph.get_node(ctrl_id) is not None:
                # Вес = score риска (нормализованный, если >25 то 25 — max из 5*5)
                score = risk.get("risk_score", risk.get("score", 9))
                weight = min(float(score) / 25.0, 1.0)
                edge_added = graph.add_edge_safe(GraphEdge(
                    source_id=ctrl_id,
                    target_id=risk_id,
                    edge_type="has_risk",
                    weight=weight,
                ))
                if edge_added:
                    edge_count += 1

        log.debug(
            "GraphBuilder: добавлено %d risk-узлов, %d рёбер has_risk",
            risk_count, edge_count,
        )

    # ── Добавление Vendor-узлов ────────────────────────────────────────────

    def _add_vendor_nodes(
        self,
        graph: ComplianceGraph,
        vendors: list[dict[str, Any]],
        risk_register: list[dict[str, Any]],
    ) -> None:
        """
        Добавляет узлы типа 'vendor' и рёбра risk → vendor (owned_by).

        Логика привязки risk → vendor:
        - Риски категории "vendor" или "third_party" → к критическому вендору
        - Явная связь через vendor_id в данных риска (если есть)
        - Риски связанные с CC9.2 (vendor management) → к critical-вендорам

        В текущей структуре данных явного vendor_id в рисках нет,
        поэтому выполняем эвристику по категории контроля.
        """
        vendor_count = 0

        # Индекс vendor_id → vendor для быстрого поиска
        vendor_index: dict[str, dict[str, Any]] = {}
        for vendor in vendors:
            vendor_id = vendor.get("id")
            if not vendor_id:
                continue

            if graph.get_node(vendor_id) is None:
                graph.add_node(GraphNode(
                    node_id=vendor_id,
                    node_type="vendor",
                    data={
                        "vendor_id": vendor_id,
                        "name": vendor.get("name", ""),
                        "category": vendor.get("category", ""),
                        "criticality": vendor.get("criticality", "medium"),
                        "status": vendor.get("status", "pending"),
                        "dpa_signed": vendor.get("dpa_signed", False),
                        "risk_score": vendor.get("risk_score", 50),
                    },
                    metadata={
                        "last_review_date": vendor.get("last_review_date", ""),
                        "next_review_date": vendor.get("next_review_date", ""),
                        "notes": vendor.get("notes", ""),
                    },
                ))
                vendor_count += 1
                vendor_index[vendor_id] = vendor

        # Находим критических вендоров для эвристики
        critical_vendors: list[str] = [
            v["id"] for v in vendors
            if v.get("criticality") in ("critical", "high") and v.get("id")
        ]

        # Строим рёбра risk → vendor
        edge_count = 0
        for risk in risk_register:
            risk_id = risk.get("id")
            if not risk_id or graph.get_node(risk_id) is None:
                continue

            # Явный vendor_id в данных риска
            vendor_id_direct = risk.get("vendor_id")
            if vendor_id_direct and graph.get_node(vendor_id_direct) is not None:
                graph.add_edge_safe(GraphEdge(
                    source_id=risk_id,
                    target_id=vendor_id_direct,
                    edge_type="owned_by",
                    weight=1.0,
                ))
                edge_count += 1
                continue

            # Эвристика: контроль CC9.2 (vendor management) → critical vendors
            ctrl_id = risk.get("control_id", "")
            if ctrl_id == "CC9.2" and critical_vendors:
                for vid in critical_vendors[:3]:  # не более 3 критических
                    graph.add_edge_safe(GraphEdge(
                        source_id=risk_id,
                        target_id=vid,
                        edge_type="owned_by",
                        weight=0.8,
                    ))
                    edge_count += 1

        log.debug(
            "GraphBuilder: добавлено %d vendor-узлов, %d рёбер owned_by",
            vendor_count, edge_count,
        )

    # ── Добавление рёбер depends_on из онтологии ──────────────────────────

    def _add_dependency_edges(self, graph: ComplianceGraph) -> None:
        """
        Добавляет рёбра control → control (depends_on) на основе онтологии.

        Источник: compliance_ontology.py → ControlOntology.requires
        requires содержит строки типа "MFA", "RBAC", "PasswordPolicy" —
        это не control_id, поэтому маппим через имена контролей.

        В дополнение к semantic requires добавляем структурные зависимости:
        - CC6.2 depends_on CC6.1 (authentication требует access management)
        - CC6.3 depends_on CC6.2
        - CC7.2 depends_on CC7.1
        - CC7.3 depends_on CC7.2
        - CC7.4 depends_on CC7.3
        - CC7.5 depends_on CC7.4
        """
        # Структурные зависимости SOC2 (TSC логика)
        structural_deps: list[tuple[str, str]] = [
            ("CC6.2", "CC6.1"),
            ("CC6.3", "CC6.1"),
            ("CC6.3", "CC6.2"),
            ("CC6.5", "CC6.1"),
            ("CC7.2", "CC7.1"),
            ("CC7.3", "CC7.2"),
            ("CC7.4", "CC7.3"),
            ("CC7.5", "CC7.4"),
            ("CC4.2", "CC4.1"),
            ("CC3.2", "CC3.1"),
            ("CC9.2", "CC3.2"),
            ("A1.3", "A1.1"),
            ("A1.3", "A1.2"),
        ]

        edge_count = 0
        for source_id, target_id in structural_deps:
            if (
                graph.get_node(source_id) is not None
                and graph.get_node(target_id) is not None
            ):
                added = graph.add_edge_safe(GraphEdge(
                    source_id=source_id,
                    target_id=target_id,
                    edge_type="depends_on",
                    weight=1.0,
                ))
                if added:
                    edge_count += 1

        log.debug(
            "GraphBuilder: добавлено %d рёбер depends_on",
            edge_count,
        )

    # ── Добавление AI Decision-узлов (опционально) ────────────────────────

    def _add_ai_decision_nodes(
        self,
        graph: ComplianceGraph,
        ai_decisions: list[dict[str, Any]],
    ) -> None:
        """
        Добавляет decision-узлы из ai_decisions.json как policy-узлы.

        AI decisions связаны с контролями через control_id.
        Ребро: decision → control (applies_to).
        """
        added_nodes = 0
        added_edges = 0

        for decision in ai_decisions:
            decision_id = decision.get("id") or decision.get("decision_id")
            if not decision_id:
                continue

            # Добавляем как policy-узел
            node_id = f"decision:{decision_id}"
            if graph.get_node(node_id) is None:
                graph.add_node(GraphNode(
                    node_id=node_id,
                    node_type="policy",
                    data={
                        "decision_id": decision_id,
                        "verdict": decision.get("verdict", ""),
                        "reasoning": decision.get("reasoning", ""),
                        "confidence": decision.get("confidence", 0.0),
                    },
                    metadata={
                        "source": "ai_decision",
                        "timestamp": decision.get("timestamp", ""),
                    },
                ))
                added_nodes += 1

            ctrl_id = decision.get("control_id")
            if ctrl_id and graph.get_node(ctrl_id) is not None:
                graph.add_edge_safe(GraphEdge(
                    source_id=node_id,
                    target_id=ctrl_id,
                    edge_type="applies_to",
                    weight=float(decision.get("confidence", 0.5)),
                ))
                added_edges += 1

        if added_nodes:
            log.debug(
                "GraphBuilder: добавлено %d AI-decision узлов, %d рёбер applies_to",
                added_nodes, added_edges,
            )

    # ── Загрузка онтологии (с мягкой обработкой ошибок) ──────────────────

    def _load_ontology(self) -> dict[str, dict[str, Any]]:
        """
        Загружает данные онтологии через compliance_ontology.py.

        Возвращает словарь {control_id: dict_данных} или пустой dict при ошибке.
        """
        try:
            from compliance_ontology import get_ontology_engine
            engine = get_ontology_engine()
            result: dict[str, dict[str, Any]] = {}
            for ctrl in engine.get_all():
                result[ctrl.id] = {
                    "title": ctrl.title,
                    "category": ctrl.category,
                    "risk_weight": ctrl.risk_weight,
                    "sla_hours": ctrl.sla_hours,
                    "auto_remediable": ctrl.auto_remediable,
                    "owner_role": ctrl.owner_role,
                    "requires": list(ctrl.requires),
                    "evidence_types": list(ctrl.evidence_types),
                }
            return result
        except Exception as exc:
            log.warning("Онтология недоступна, используем базовые данные: %s", exc)
            return {}


# ── Thread-safe singleton ─────────────────────────────────────────────────────

_builder_instance: Optional[GraphBuilder] = None
_singleton_lock = threading.Lock()


def get_graph_builder() -> GraphBuilder:
    """
    Получить singleton GraphBuilder (thread-safe ленивая инициализация).
    """
    global _builder_instance
    if _builder_instance is None:
        with _singleton_lock:
            if _builder_instance is None:
                _builder_instance = GraphBuilder()
    return _builder_instance


def get_compliance_graph() -> ComplianceGraph:
    """
    Удобная функция: получить актуальный граф из singleton builder.

    Используется в роутерах FastAPI.
    """
    return get_graph_builder().build_from_state()
