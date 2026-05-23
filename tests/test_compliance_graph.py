"""
test_compliance_graph.py — Тесты для compliance_graph.py и graph_builder.py.

Минимум 20 тестов:
  - добавление узлов и рёбер
  - валидация типов
  - поиск пути (BFS)
  - propagate_risk
  - get_control_context
  - find_affected_controls
  - get_compliance_subgraph
  - сериализация to_dict / from_dict
  - граф-статистика (get_summary)
  - GraphBuilder.build_from_state
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock

from compliance_graph import (
    ComplianceGraph,
    GraphEdge,
    GraphNode,
    NODE_TYPES,
    EDGE_TYPES,
)


# ══════════════════════════════════════════════════════════════════════════════
# Фикстуры
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def empty_graph() -> ComplianceGraph:
    """Пустой граф для каждого теста."""
    return ComplianceGraph()


@pytest.fixture
def control_node() -> GraphNode:
    return GraphNode(
        node_id="CC6.1",
        node_type="control",
        data={"title": "Logical Access Controls", "risk_weight": 0.9},
        metadata={"frameworks": ["soc2"]},
    )


@pytest.fixture
def risk_node() -> GraphNode:
    return GraphNode(
        node_id="RISK-001",
        node_type="risk",
        data={"title": "Credential Theft", "score": 15, "status": "open"},
        metadata={"source": "control"},
    )


@pytest.fixture
def evidence_node() -> GraphNode:
    return GraphNode(
        node_id="ev-uuid-001",
        node_type="evidence",
        data={"control_id": "CC6.1"},
        metadata={"source": "controls_map"},
    )


@pytest.fixture
def vendor_node() -> GraphNode:
    return GraphNode(
        node_id="VND-001",
        node_type="vendor",
        data={"name": "Amazon Web Services", "criticality": "critical"},
        metadata={},
    )


@pytest.fixture
def policy_node() -> GraphNode:
    return GraphNode(
        node_id="POL-001",
        node_type="policy",
        data={"title": "Access Control Policy"},
        metadata={},
    )


@pytest.fixture
def small_graph(
    empty_graph: ComplianceGraph,
    control_node: GraphNode,
    risk_node: GraphNode,
    evidence_node: GraphNode,
    vendor_node: GraphNode,
    policy_node: GraphNode,
) -> ComplianceGraph:
    """
    Граф с 5 узлами и связями для большинства тестов:
      CC6.1 --has_risk--> RISK-001
      CC6.1 --has_evidence--> ev-uuid-001
      RISK-001 --owned_by--> VND-001
      POL-001 --applies_to--> CC6.1
    """
    empty_graph.add_node(control_node)
    empty_graph.add_node(risk_node)
    empty_graph.add_node(evidence_node)
    empty_graph.add_node(vendor_node)
    empty_graph.add_node(policy_node)

    empty_graph.add_edge(GraphEdge("CC6.1", "RISK-001", "has_risk", weight=0.6))
    empty_graph.add_edge(GraphEdge("CC6.1", "ev-uuid-001", "has_evidence", weight=1.0))
    empty_graph.add_edge(GraphEdge("RISK-001", "VND-001", "owned_by", weight=1.0))
    empty_graph.add_edge(GraphEdge("POL-001", "CC6.1", "applies_to", weight=0.9))

    return empty_graph


# ══════════════════════════════════════════════════════════════════════════════
# Тест 1–3: GraphNode — создание и валидация
# ══════════════════════════════════════════════════════════════════════════════

def test_graph_node_creation_valid():
    """Узел создаётся с допустимым node_type."""
    node = GraphNode(node_id="CC6.1", node_type="control", data={"title": "Test"})
    assert node.node_id == "CC6.1"
    assert node.node_type == "control"
    assert node.data["title"] == "Test"


def test_graph_node_invalid_type_raises():
    """Недопустимый node_type вызывает ValueError."""
    with pytest.raises(ValueError, match="Недопустимый тип узла"):
        GraphNode(node_id="X-001", node_type="unknown_type")


def test_graph_node_empty_id_raises():
    """Пустой node_id вызывает ValueError."""
    with pytest.raises(ValueError, match="node_id"):
        GraphNode(node_id="", node_type="control")


# ══════════════════════════════════════════════════════════════════════════════
# Тест 4–6: GraphEdge — создание и валидация
# ══════════════════════════════════════════════════════════════════════════════

def test_graph_edge_creation_valid():
    """Ребро создаётся с допустимыми параметрами."""
    edge = GraphEdge("CC6.1", "RISK-001", "has_risk", weight=0.7)
    assert edge.source_id == "CC6.1"
    assert edge.target_id == "RISK-001"
    assert edge.edge_type == "has_risk"
    assert edge.weight == pytest.approx(0.7)


def test_graph_edge_invalid_type_raises():
    """Недопустимый edge_type вызывает ValueError."""
    with pytest.raises(ValueError, match="Недопустимый тип ребра"):
        GraphEdge("A", "B", "unknown_edge_type")


def test_graph_edge_negative_weight_raises():
    """Отрицательный weight вызывает ValueError."""
    with pytest.raises(ValueError, match="weight"):
        GraphEdge("A", "B", "has_risk", weight=-1.0)


# ══════════════════════════════════════════════════════════════════════════════
# Тест 7–9: ComplianceGraph — базовые операции
# ══════════════════════════════════════════════════════════════════════════════

def test_add_node_and_get_node(empty_graph: ComplianceGraph, control_node: GraphNode):
    """Добавленный узел можно получить по ID."""
    empty_graph.add_node(control_node)
    retrieved = empty_graph.get_node("CC6.1")
    assert retrieved is not None
    assert retrieved.node_id == "CC6.1"
    assert retrieved.node_type == "control"


def test_add_node_upsert(empty_graph: ComplianceGraph):
    """Повторное добавление узла перезаписывает данные (upsert)."""
    node1 = GraphNode("N1", "control", data={"v": 1})
    node2 = GraphNode("N1", "control", data={"v": 2})
    empty_graph.add_node(node1)
    empty_graph.add_node(node2)
    assert empty_graph.get_node("N1").data["v"] == 2
    assert empty_graph.node_count == 1


def test_add_edge_requires_existing_nodes(empty_graph: ComplianceGraph, control_node: GraphNode):
    """Добавление ребра к несуществующему узлу вызывает ValueError."""
    empty_graph.add_node(control_node)
    with pytest.raises(ValueError, match="не найден в графе"):
        empty_graph.add_edge(GraphEdge("CC6.1", "NONEXISTENT", "has_risk"))


# ══════════════════════════════════════════════════════════════════════════════
# Тест 10–11: get_neighbors
# ══════════════════════════════════════════════════════════════════════════════

def test_get_neighbors_returns_connected_nodes(small_graph: ComplianceGraph):
    """get_neighbors возвращает правильных соседей CC6.1."""
    neighbors = small_graph.get_neighbors("CC6.1")
    neighbor_ids = {n.node_id for n in neighbors}
    assert "RISK-001" in neighbor_ids
    assert "ev-uuid-001" in neighbor_ids


def test_get_neighbors_with_edge_type_filter(small_graph: ComplianceGraph):
    """get_neighbors с фильтром edge_type возвращает только нужных соседей."""
    risk_neighbors = small_graph.get_neighbors("CC6.1", edge_type="has_risk")
    evidence_neighbors = small_graph.get_neighbors("CC6.1", edge_type="has_evidence")
    assert len(risk_neighbors) == 1
    assert risk_neighbors[0].node_id == "RISK-001"
    assert len(evidence_neighbors) == 1
    assert evidence_neighbors[0].node_id == "ev-uuid-001"


# ══════════════════════════════════════════════════════════════════════════════
# Тест 12–13: find_path (BFS)
# ══════════════════════════════════════════════════════════════════════════════

def test_find_path_direct_connection(small_graph: ComplianceGraph):
    """BFS находит прямой путь CC6.1 → RISK-001."""
    path = small_graph.find_path("CC6.1", "RISK-001")
    assert path == ["CC6.1", "RISK-001"]


def test_find_path_multi_hop(small_graph: ComplianceGraph):
    """BFS находит многошаговый путь CC6.1 → RISK-001 → VND-001."""
    path = small_graph.find_path("CC6.1", "VND-001")
    assert path[0] == "CC6.1"
    assert path[-1] == "VND-001"
    assert len(path) == 3


def test_find_path_no_path_returns_empty(small_graph: ComplianceGraph):
    """find_path возвращает пустой список если путь недостижим."""
    # VND-001 не имеет исходящих рёбер к CC6.1
    path = small_graph.find_path("VND-001", "CC6.1")
    assert path == []


def test_find_path_same_node(small_graph: ComplianceGraph):
    """find_path для одного и того же узла возвращает [node_id]."""
    path = small_graph.find_path("CC6.1", "CC6.1")
    assert path == ["CC6.1"]


def test_find_path_nonexistent_node(small_graph: ComplianceGraph):
    """find_path с несуществующим узлом возвращает пустой список."""
    path = small_graph.find_path("CC6.1", "NONEXISTENT")
    assert path == []


# ══════════════════════════════════════════════════════════════════════════════
# Тест 16–17: get_control_context
# ══════════════════════════════════════════════════════════════════════════════

def test_get_control_context_returns_full_context(small_graph: ComplianceGraph):
    """get_control_context возвращает все связанные сущности."""
    ctx = small_graph.get_control_context("CC6.1")
    assert ctx["control"]["node_id"] == "CC6.1"
    assert len(ctx["risks"]) == 1
    assert ctx["risks"][0]["node_id"] == "RISK-001"
    assert len(ctx["evidences"]) == 1
    assert len(ctx["policies"]) == 1
    assert ctx["policies"][0]["node_id"] == "POL-001"
    # Вендор достигается через риск
    assert len(ctx["vendors"]) == 1


def test_get_control_context_not_found_returns_empty(small_graph: ComplianceGraph):
    """get_control_context для несуществующего контроля возвращает пустой dict."""
    ctx = small_graph.get_control_context("NONEXISTENT")
    assert ctx == {}


# ══════════════════════════════════════════════════════════════════════════════
# Тест 18–19: propagate_risk
# ══════════════════════════════════════════════════════════════════════════════

def test_propagate_risk_returns_affected_controls(small_graph: ComplianceGraph):
    """propagate_risk возвращает контроли затронутые риском RISK-001."""
    affected = small_graph.propagate_risk("RISK-001")
    assert len(affected) == 1
    assert affected[0]["control"]["node_id"] == "CC6.1"
    assert affected[0]["risk"]["node_id"] == "RISK-001"


def test_propagate_risk_unknown_risk_returns_empty(small_graph: ComplianceGraph):
    """propagate_risk для несуществующего риска возвращает пустой список."""
    result = small_graph.propagate_risk("RISK-UNKNOWN")
    assert result == []


# ══════════════════════════════════════════════════════════════════════════════
# Тест 20: find_affected_controls (vendor)
# ══════════════════════════════════════════════════════════════════════════════

def test_find_affected_controls_for_vendor(small_graph: ComplianceGraph):
    """find_affected_controls возвращает контроли зависимые от VND-001."""
    affected = small_graph.find_affected_controls("VND-001")
    assert len(affected) >= 1
    ctrl_ids = [a["control"]["node_id"] for a in affected]
    assert "CC6.1" in ctrl_ids


# ══════════════════════════════════════════════════════════════════════════════
# Тест 21: get_summary
# ══════════════════════════════════════════════════════════════════════════════

def test_get_summary_counts(small_graph: ComplianceGraph):
    """get_summary возвращает корректные счётчики."""
    summary = small_graph.get_summary()
    assert summary["node_count"] == 5
    assert summary["edge_count"] == 4
    assert "nodes_by_type" in summary
    assert "edges_by_type" in summary
    assert summary["nodes_by_type"]["control"] == 1
    assert summary["nodes_by_type"]["risk"] == 1
    assert summary["nodes_by_type"]["vendor"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# Тест 22–23: сериализация to_dict / from_dict
# ══════════════════════════════════════════════════════════════════════════════

def test_graph_node_serialization():
    """GraphNode.to_dict() и from_dict() — roundtrip."""
    node = GraphNode("CC6.1", "control", data={"v": 42}, metadata={"fw": "soc2"})
    d = node.to_dict()
    restored = GraphNode.from_dict(d)
    assert restored.node_id == "CC6.1"
    assert restored.node_type == "control"
    assert restored.data["v"] == 42
    assert restored.metadata["fw"] == "soc2"


def test_graph_edge_serialization():
    """GraphEdge.to_dict() и from_dict() — roundtrip."""
    edge = GraphEdge("A", "B", "has_risk", weight=0.75)
    d = edge.to_dict()
    restored = GraphEdge.from_dict(d)
    assert restored.source_id == "A"
    assert restored.target_id == "B"
    assert restored.edge_type == "has_risk"
    assert restored.weight == pytest.approx(0.75)


def test_graph_full_serialization(small_graph: ComplianceGraph):
    """ComplianceGraph.to_dict() и from_dict() — roundtrip с сохранением структуры."""
    d = small_graph.to_dict()
    restored = ComplianceGraph.from_dict(d)

    assert restored.node_count == small_graph.node_count
    assert restored.edge_count == small_graph.edge_count

    # Проверяем что узлы и связи сохранены
    ctrl = restored.get_node("CC6.1")
    assert ctrl is not None
    risk_neighbors = restored.get_neighbors("CC6.1", edge_type="has_risk")
    assert len(risk_neighbors) == 1


# ══════════════════════════════════════════════════════════════════════════════
# Тест 25: get_compliance_subgraph
# ══════════════════════════════════════════════════════════════════════════════

def test_get_compliance_subgraph_soc2(small_graph: ComplianceGraph):
    """get_compliance_subgraph('soc2') включает контроли с frameworks=['soc2']."""
    subgraph = small_graph.get_compliance_subgraph(framework="soc2")
    # CC6.1 имеет metadata.frameworks=["soc2"] — должен попасть в подграф
    ctrl = subgraph.get_node("CC6.1")
    assert ctrl is not None


# ══════════════════════════════════════════════════════════════════════════════
# Тест 26: add_edge_safe не бросает исключение при отсутствии узлов
# ══════════════════════════════════════════════════════════════════════════════

def test_add_edge_safe_returns_false_on_missing_node(empty_graph: ComplianceGraph):
    """add_edge_safe возвращает False если узел не найден."""
    result = empty_graph.add_edge_safe(GraphEdge("MISSING_A", "MISSING_B", "has_risk"))
    assert result is False


# ══════════════════════════════════════════════════════════════════════════════
# Тест 27: GraphBuilder интеграционный тест
# ══════════════════════════════════════════════════════════════════════════════

def test_graph_builder_build_from_state():
    """
    GraphBuilder.build_from_state() строит граф из реальных файлов проекта.
    Проверяет минимальные инварианты: наличие control/risk узлов.
    """
    from graph_builder import GraphBuilder
    builder = GraphBuilder()
    graph = builder.build_from_state()

    summary = graph.get_summary()
    # Граф не пустой — должны быть хотя бы контроли
    assert summary["node_count"] > 0
    # Должны присутствовать узлы типа control
    assert summary["nodes_by_type"].get("control", 0) > 0


# ══════════════════════════════════════════════════════════════════════════════
# Тест 28: rebuild() сбрасывает кэш
# ══════════════════════════════════════════════════════════════════════════════

def test_graph_builder_rebuild_clears_cache():
    """
    GraphBuilder.rebuild() возвращает новый граф (не тот же объект что в кэше).
    """
    from graph_builder import GraphBuilder
    builder = GraphBuilder()
    g1 = builder.build_from_state()
    g2 = builder.rebuild()
    # Объекты разные (rebuild создаёт новый граф)
    assert g1 is not g2


# ══════════════════════════════════════════════════════════════════════════════
# Тест 29: граф-статистика connected_components
# ══════════════════════════════════════════════════════════════════════════════

def test_connected_components_isolated_nodes():
    """Два изолированных узла образуют 2 компоненты связности."""
    g = ComplianceGraph()
    g.add_node(GraphNode("A", "control"))
    g.add_node(GraphNode("B", "risk"))
    summary = g.get_summary()
    assert summary["connected_components"] == 2


def test_connected_components_connected_nodes():
    """Два связанных узла образуют 1 компоненту."""
    g = ComplianceGraph()
    g.add_node(GraphNode("A", "control"))
    g.add_node(GraphNode("B", "risk"))
    g.add_edge(GraphEdge("A", "B", "has_risk"))
    summary = g.get_summary()
    assert summary["connected_components"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# Тест 31: depends_on рёбра
# ══════════════════════════════════════════════════════════════════════════════

def test_depends_on_edge_and_context():
    """
    Контроль CC6.2, зависящий от CC6.1:
    get_control_context("CC6.2") должен включить его в depends_on.
    """
    g = ComplianceGraph()
    ctrl1 = GraphNode("CC6.1", "control", data={"title": "Access Management"})
    ctrl2 = GraphNode("CC6.2", "control", data={"title": "Authentication"})
    g.add_node(ctrl1)
    g.add_node(ctrl2)
    g.add_edge(GraphEdge("CC6.2", "CC6.1", "depends_on", weight=1.0))

    ctx = g.get_control_context("CC6.2")
    assert len(ctx["depends_on"]) == 1
    assert ctx["depends_on"][0]["node_id"] == "CC6.1"

    ctx_cc6_1 = g.get_control_context("CC6.1")
    assert len(ctx_cc6_1["required_by"]) == 1
    assert ctx_cc6_1["required_by"][0]["node_id"] == "CC6.2"


# ══════════════════════════════════════════════════════════════════════════════
# Тест 32: NODE_TYPES и EDGE_TYPES константы
# ══════════════════════════════════════════════════════════════════════════════

def test_node_types_coverage():
    """Все ожидаемые типы узлов присутствуют в NODE_TYPES."""
    expected = {"control", "risk", "evidence", "asset", "vendor", "policy"}
    assert expected == NODE_TYPES


def test_edge_types_coverage():
    """Все ожидаемые типы рёбер присутствуют в EDGE_TYPES."""
    expected = {
        "has_evidence", "has_risk", "mitigates",
        "applies_to", "owned_by", "depends_on",
    }
    assert expected == EDGE_TYPES
