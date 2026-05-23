"""
compliance_graph.py — In-memory граф связей между compliance-сущностями.

Объединяет Risk, Controls, Evidence, Vendor, Asset, Policy в единый граф
для AI reasoning поверх изолированных доменов.

Граф живёт только в памяти (query-layer над JSON-данными),
никакой записи в БД не производится.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

from log_config import get_logger

log = get_logger(__name__)

# ── Допустимые типы узлов ──────────────────────────────────────────────────────

NODE_TYPES = frozenset({
    "control",
    "risk",
    "evidence",
    "asset",
    "vendor",
    "policy",
})

# ── Допустимые типы рёбер ──────────────────────────────────────────────────────

EDGE_TYPES = frozenset({
    "has_evidence",   # control → evidence
    "has_risk",       # control → risk
    "mitigates",      # control → risk (обратное к has_risk)
    "applies_to",     # policy → control
    "owned_by",       # risk → vendor  /  asset → vendor
    "depends_on",     # control → control (из ontology requires)
})


# ── Узел графа ─────────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    """
    Один узел compliance-графа.

    node_id   — уникальный идентификатор (например, "CC6.1", "RISK-001", "VND-002")
    node_type — одна из констант NODE_TYPES
    data      — основные атрибуты сущности (title, status, score, …)
    metadata  — дополнительные атрибуты (source, framework, timestamps, …)
    """
    node_id: str
    node_type: str
    data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.node_type not in NODE_TYPES:
            raise ValueError(
                f"Недопустимый тип узла: {self.node_type!r}. "
                f"Допустимые значения: {sorted(NODE_TYPES)}"
            )
        if not self.node_id:
            raise ValueError("node_id не может быть пустой строкой")

    def to_dict(self) -> dict[str, Any]:
        """Сериализация узла в словарь."""
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "data": self.data,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GraphNode":
        """Десериализация узла из словаря."""
        return cls(
            node_id=d["node_id"],
            node_type=d["node_type"],
            data=d.get("data", {}),
            metadata=d.get("metadata", {}),
        )


# ── Ребро графа ────────────────────────────────────────────────────────────────

@dataclass
class GraphEdge:
    """
    Направленное ребро между двумя узлами compliance-графа.

    source_id — откуда (например, "CC6.1")
    target_id — куда (например, "RISK-001")
    edge_type — одна из констант EDGE_TYPES
    weight    — вес связи [0.0, ∞), влияет на приоритизацию
    """
    source_id: str
    target_id: str
    edge_type: str
    weight: float = 1.0

    def __post_init__(self) -> None:
        if self.edge_type not in EDGE_TYPES:
            raise ValueError(
                f"Недопустимый тип ребра: {self.edge_type!r}. "
                f"Допустимые значения: {sorted(EDGE_TYPES)}"
            )
        if self.weight < 0.0:
            raise ValueError(f"weight не может быть отрицательным: {self.weight}")

    def to_dict(self) -> dict[str, Any]:
        """Сериализация ребра в словарь."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type,
            "weight": self.weight,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GraphEdge":
        """Десериализация ребра из словаря."""
        return cls(
            source_id=d["source_id"],
            target_id=d["target_id"],
            edge_type=d["edge_type"],
            weight=float(d.get("weight", 1.0)),
        )


# ── Compliance Graph ───────────────────────────────────────────────────────────

class ComplianceGraph:
    """
    In-memory ориентированный мультиграф compliance-сущностей.

    Хранит:
      - узлы (nodes): Control, Risk, Evidence, Vendor, Asset, Policy
      - рёбра (edges): направленные связи с типами и весами

    Поддерживает:
      - поиск кратчайшего пути (BFS)
      - распространение рисков по контролям
      - получение полного контекста контроля
      - подграф по фреймворку
      - сериализацию в/из dict
    """

    def __init__(self) -> None:
        # Словарь узлов: node_id → GraphNode
        self._nodes: dict[str, GraphNode] = {}

        # Смежность: source_id → list[GraphEdge]
        self._adj: dict[str, list[GraphEdge]] = defaultdict(list)

        # Обратные связи: target_id → list[GraphEdge] (для reverse traversal)
        self._radj: dict[str, list[GraphEdge]] = defaultdict(list)

        # Счётчик всех рёбер
        self._edge_count: int = 0

    # ── Мутирующие методы ──────────────────────────────────────────────────

    def add_node(self, node: GraphNode) -> None:
        """
        Добавить узел в граф. Если узел с таким node_id уже существует —
        данные перезаписываются (upsert-семантика).
        """
        self._nodes[node.node_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """
        Добавить ребро. Оба узла должны существовать в графе.
        Дублирующиеся рёбра (source, target, type) добавляются повторно
        — для мультиграфа это нормально.

        Raises:
            ValueError: если source или target не существуют.
        """
        if edge.source_id not in self._nodes:
            raise ValueError(
                f"Узел-источник не найден в графе: {edge.source_id!r}"
            )
        if edge.target_id not in self._nodes:
            raise ValueError(
                f"Узел-цель не найден в графе: {edge.target_id!r}"
            )
        self._adj[edge.source_id].append(edge)
        self._radj[edge.target_id].append(edge)
        self._edge_count += 1

    def add_edge_safe(self, edge: GraphEdge) -> bool:
        """
        Добавить ребро только если оба узла существуют.
        Возвращает True при успехе, False если узел(ы) не найдены.
        Не бросает исключений — удобно при массовом импорте данных.
        """
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            log.debug(
                "Пропуск ребра %s→%s: узлы не найдены",
                edge.source_id,
                edge.target_id,
            )
            return False
        self.add_edge(edge)
        return True

    # ── Чтение ────────────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Получить узел по ID или None."""
        return self._nodes.get(node_id)

    def get_neighbors(
        self,
        node_id: str,
        edge_type: Optional[str] = None,
    ) -> list[GraphNode]:
        """
        Получить список узлов-соседей (исходящие рёбра).

        Args:
            node_id:   ID исходного узла
            edge_type: фильтр по типу ребра (None = все типы)

        Returns:
            Список GraphNode-соседей (без дублей, сохраняя порядок).
        """
        edges = self._adj.get(node_id, [])
        if edge_type is not None:
            edges = [e for e in edges if e.edge_type == edge_type]
        # Используем dict для удаления дублей с сохранением порядка
        seen: dict[str, GraphNode] = {}
        for edge in edges:
            if edge.target_id not in seen and edge.target_id in self._nodes:
                seen[edge.target_id] = self._nodes[edge.target_id]
        return list(seen.values())

    def get_reverse_neighbors(
        self,
        node_id: str,
        edge_type: Optional[str] = None,
    ) -> list[GraphNode]:
        """
        Получить список узлов-соседей по обратным рёбрам (входящие связи).

        Args:
            node_id:   ID целевого узла
            edge_type: фильтр по типу ребра (None = все типы)
        """
        edges = self._radj.get(node_id, [])
        if edge_type is not None:
            edges = [e for e in edges if e.edge_type == edge_type]
        seen: dict[str, GraphNode] = {}
        for edge in edges:
            if edge.source_id not in seen and edge.source_id in self._nodes:
                seen[edge.source_id] = self._nodes[edge.source_id]
        return list(seen.values())

    def get_edges(
        self,
        source_id: str,
        edge_type: Optional[str] = None,
    ) -> list[GraphEdge]:
        """Получить исходящие рёбра узла с опциональной фильтрацией по типу."""
        edges = self._adj.get(source_id, [])
        if edge_type is not None:
            return [e for e in edges if e.edge_type == edge_type]
        return list(edges)

    # ── Алгоритмы обхода ──────────────────────────────────────────────────

    def find_path(self, from_id: str, to_id: str) -> list[str]:
        """
        BFS кратчайший путь между двумя узлами.

        Args:
            from_id: ID начального узла
            to_id:   ID конечного узла

        Returns:
            Список node_id образующих путь (включая from и to).
            Пустой список если путь не найден или узлы не существуют.
        """
        if from_id not in self._nodes or to_id not in self._nodes:
            return []
        if from_id == to_id:
            return [from_id]

        # BFS: очередь хранит (текущий_id, путь_до_него)
        queue: deque[tuple[str, list[str]]] = deque([(from_id, [from_id])])
        visited: set[str] = {from_id}

        while queue:
            current, path = queue.popleft()
            for edge in self._adj.get(current, []):
                nxt = edge.target_id
                if nxt == to_id:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt]))

        return []

    # ── Compliance-специфические методы ───────────────────────────────────

    def get_control_context(self, control_id: str) -> dict[str, Any]:
        """
        Полный контекст контроля из графа.

        Возвращает сам контроль + все связанные сущности:
          - risks:     риски контроля (has_risk)
          - evidences: доказательства (has_evidence)
          - vendors:   вендоры через риски (owned_by)
          - policies:  политики, применяемые к контролю (applies_to)
          - depends_on:   контроли-зависимости (depends_on)
          - required_by:  контроли которые зависят от этого (обратные depends_on)

        Args:
            control_id: ID контроля, например "CC6.1"

        Returns:
            dict с ключами control, risks, evidences, vendors, policies,
            depends_on, required_by. Пустой dict если контроль не найден.
        """
        node = self._nodes.get(control_id)
        if node is None or node.node_type != "control":
            return {}

        # Прямые соседи
        risks = self.get_neighbors(control_id, edge_type="has_risk")
        evidences = self.get_neighbors(control_id, edge_type="has_evidence")
        depends_on = self.get_neighbors(control_id, edge_type="depends_on")

        # Политики, применённые к контролю (обратные рёбра applies_to)
        policies = self.get_reverse_neighbors(control_id, edge_type="applies_to")

        # Вендоры через риски
        vendor_ids: dict[str, GraphNode] = {}
        for risk in risks:
            for v in self.get_neighbors(risk.node_id, edge_type="owned_by"):
                vendor_ids[v.node_id] = v

        # Контроли которые зависят от текущего
        required_by = self.get_reverse_neighbors(control_id, edge_type="depends_on")

        return {
            "control": node.to_dict(),
            "risks": [r.to_dict() for r in risks],
            "evidences": [e.to_dict() for e in evidences],
            "vendors": [v.to_dict() for v in vendor_ids.values()],
            "policies": [p.to_dict() for p in policies],
            "depends_on": [d.to_dict() for d in depends_on],
            "required_by": [r.to_dict() for r in required_by],
            "summary": {
                "risk_count": len(risks),
                "evidence_count": len(evidences),
                "vendor_count": len(vendor_ids),
                "policy_count": len(policies),
                "depends_on_count": len(depends_on),
                "required_by_count": len(required_by),
            },
        }

    def propagate_risk(self, risk_id: str) -> list[dict[str, Any]]:
        """
        Распространение риска: какие контроли затронуты при наличии данного риска.

        Проходит по обратным рёбрам has_risk (control → risk),
        возвращает список контролей с метаданными риска.

        Args:
            risk_id: ID риска, например "RISK-001"

        Returns:
            Список dict {control: ..., risk_weight: float, edge_weight: float}.
            Пустой список если риск не найден или нет связанных контролей.
        """
        risk_node = self._nodes.get(risk_id)
        if risk_node is None or risk_node.node_type != "risk":
            return []

        # Контроли, ссылающиеся на этот риск (обратные has_risk)
        affected_edges = [
            e for e in self._radj.get(risk_id, [])
            if e.edge_type == "has_risk"
        ]

        result: list[dict[str, Any]] = []
        for edge in affected_edges:
            ctrl_node = self._nodes.get(edge.source_id)
            if ctrl_node and ctrl_node.node_type == "control":
                result.append({
                    "control": ctrl_node.to_dict(),
                    "risk": risk_node.to_dict(),
                    "edge_weight": edge.weight,
                    # risk_weight берём из данных контроля если доступен
                    "control_risk_weight": ctrl_node.data.get("risk_weight", 1.0),
                })

        # Сортируем по убыванию веса контроля (самые критичные первыми)
        result.sort(key=lambda x: x["control_risk_weight"], reverse=True)
        return result

    def find_affected_controls(self, vendor_id: str) -> list[dict[str, Any]]:
        """
        Какие контроли зависят от вендора.

        Путь: vendor ← owned_by ← risk ← has_risk ← control

        Args:
            vendor_id: ID вендора, например "VND-001"

        Returns:
            Список dict {control, risk, vendor}.
        """
        vendor_node = self._nodes.get(vendor_id)
        if vendor_node is None or vendor_node.node_type != "vendor":
            return []

        # Риски принадлежащие вендору (обратные owned_by)
        risk_edges = [
            e for e in self._radj.get(vendor_id, [])
            if e.edge_type == "owned_by"
        ]

        result: list[dict[str, Any]] = []
        seen_controls: set[str] = set()

        for risk_edge in risk_edges:
            risk_node = self._nodes.get(risk_edge.source_id)
            if risk_node is None or risk_node.node_type != "risk":
                continue

            # Контроли связанные с этим риском
            ctrl_edges = [
                e for e in self._radj.get(risk_node.node_id, [])
                if e.edge_type == "has_risk"
            ]
            for ctrl_edge in ctrl_edges:
                ctrl_node = self._nodes.get(ctrl_edge.source_id)
                if (
                    ctrl_node
                    and ctrl_node.node_type == "control"
                    and ctrl_node.node_id not in seen_controls
                ):
                    seen_controls.add(ctrl_node.node_id)
                    result.append({
                        "control": ctrl_node.to_dict(),
                        "risk": risk_node.to_dict(),
                        "vendor": vendor_node.to_dict(),
                    })

        return result

    def get_compliance_subgraph(self, framework: str = "soc2") -> "ComplianceGraph":
        """
        Подграф для конкретного фреймворка.

        Фильтрует узлы типа "control" у которых в metadata.frameworks
        содержится указанный фреймворк, и переносит все связанные с ними
        рёбра и узлы в новый граф.

        Args:
            framework: идентификатор фреймворка ("soc2", "iso27001", "nist", "cis")

        Returns:
            Новый ComplianceGraph с отфильтрованными узлами и рёбрами.
        """
        subgraph = ComplianceGraph()
        framework_lower = framework.lower()

        # Фильтруем контроли по фреймворку
        target_controls: set[str] = set()
        for nid, node in self._nodes.items():
            if node.node_type != "control":
                continue
            node_frameworks = node.metadata.get("frameworks", [])
            if not node_frameworks or framework_lower in [f.lower() for f in node_frameworks]:
                target_controls.add(nid)

        # Собираем все связанные узлы и рёбра
        nodes_to_include: set[str] = set(target_controls)
        edges_to_include: list[GraphEdge] = []

        for ctrl_id in target_controls:
            for edge in self._adj.get(ctrl_id, []):
                nodes_to_include.add(edge.target_id)
                edges_to_include.append(edge)
            for edge in self._radj.get(ctrl_id, []):
                nodes_to_include.add(edge.source_id)
                edges_to_include.append(edge)

        # Добавляем узлы и рёбра в подграф
        for nid in nodes_to_include:
            if nid in self._nodes:
                subgraph.add_node(self._nodes[nid])

        for edge in edges_to_include:
            subgraph.add_edge_safe(edge)

        return subgraph

    # ── Статистика ────────────────────────────────────────────────────────

    def get_summary(self) -> dict[str, Any]:
        """
        Статистика графа: количество узлов, рёбер, связанных компонент,
        распределение по типам.
        """
        # Подсчёт узлов по типам
        type_counts: dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            type_counts[node.node_type] += 1

        # Подсчёт рёбер по типам
        edge_type_counts: dict[str, int] = defaultdict(int)
        for edges in self._adj.values():
            for edge in edges:
                edge_type_counts[edge.edge_type] += 1

        # Количество связанных компонент (неориентированный BFS)
        components = self._count_connected_components()

        return {
            "node_count": len(self._nodes),
            "edge_count": self._edge_count,
            "connected_components": components,
            "nodes_by_type": dict(type_counts),
            "edges_by_type": dict(edge_type_counts),
        }

    def _count_connected_components(self) -> int:
        """
        Считает количество связанных компонент
        (игнорируя направление рёбер).
        """
        visited: set[str] = set()
        components = 0

        for start in self._nodes:
            if start in visited:
                continue
            # BFS без учёта направления
            queue: deque[str] = deque([start])
            visited.add(start)
            while queue:
                nid = queue.popleft()
                for edge in self._adj.get(nid, []):
                    if edge.target_id not in visited:
                        visited.add(edge.target_id)
                        queue.append(edge.target_id)
                for edge in self._radj.get(nid, []):
                    if edge.source_id not in visited:
                        visited.add(edge.source_id)
                        queue.append(edge.source_id)
            components += 1

        return components

    # ── Сериализация ──────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """
        Полная сериализация графа в JSON-совместимый словарь.

        Используется для кэширования и передачи по сети.
        """
        # Собираем все уникальные рёбра
        all_edges: list[dict[str, Any]] = []
        for edges in self._adj.values():
            for edge in edges:
                all_edges.append(edge.to_dict())

        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": all_edges,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ComplianceGraph":
        """
        Десериализация графа из словаря.

        Args:
            data: словарь с ключами "nodes" и "edges"

        Returns:
            Новый ComplianceGraph.

        Raises:
            KeyError: если структура данных некорректна.
        """
        graph = cls()

        for node_data in data.get("nodes", []):
            graph.add_node(GraphNode.from_dict(node_data))

        for edge_data in data.get("edges", []):
            try:
                edge = GraphEdge.from_dict(edge_data)
                graph.add_edge_safe(edge)
            except (ValueError, KeyError) as exc:
                log.warning("Пропуск некорректного ребра при десериализации: %s", exc)

        return graph

    # ── Свойства ──────────────────────────────────────────────────────────

    @property
    def node_count(self) -> int:
        """Количество узлов в графе."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Количество рёбер в графе."""
        return self._edge_count

    def __repr__(self) -> str:
        return (
            f"<ComplianceGraph nodes={self.node_count} edges={self.edge_count}>"
        )
