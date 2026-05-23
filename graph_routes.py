"""
graph_routes.py — FastAPI роуты для Compliance Graph API.

Endpoints:
  GET /api/graph/control/{control_id}          → полный контекст контроля
  GET /api/graph/propagate/risk/{risk_id}      → затронутые контроли
  GET /api/graph/path                          → путь между узлами (?from=&to=)
  GET /api/graph/vendor/{vendor_id}/controls   → зависимые контроли вендора
  GET /api/graph/summary                       → статистика графа
  POST /api/graph/rebuild                      → пересборка графа из файлов
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from graph_builder import get_compliance_graph, get_graph_builder
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/graph", tags=["compliance-graph"])


# ── GET /api/graph/control/{control_id} ───────────────────────────────────────

@router.get(
    "/control/{control_id}",
    summary="Полный контекст контроля из графа",
    description=(
        "Возвращает контроль вместе со всеми связанными сущностями: "
        "риски, доказательства, вендоры, политики, зависимости."
    ),
)
def get_control_context(control_id: str) -> dict[str, Any]:
    """
    Получить полный граф-контекст вокруг SOC2 контроля.

    Args:
        control_id: идентификатор контроля (например, "CC6.1")

    Returns:
        Словарь с control, risks, evidences, vendors, policies, depends_on,
        required_by, summary.

    Raises:
        404: если контроль не найден в графе.
    """
    graph = get_compliance_graph()
    context = graph.get_control_context(control_id)
    if not context:
        raise HTTPException(
            status_code=404,
            detail=f"Контроль {control_id!r} не найден в compliance-графе",
        )
    return context


# ── GET /api/graph/propagate/risk/{risk_id} ───────────────────────────────────

@router.get(
    "/propagate/risk/{risk_id}",
    summary="Распространение риска на контроли",
    description=(
        "Возвращает список контролей, которые затронуты при наличии "
        "указанного риска. Отсортировано по критичности контроля (risk_weight DESC)."
    ),
)
def propagate_risk(risk_id: str) -> dict[str, Any]:
    """
    Какие контроли затронуты при наличии данного риска.

    Args:
        risk_id: идентификатор риска (например, "RISK-001")

    Returns:
        Словарь с risk_id, affected_controls (список), count.

    Raises:
        404: если риск не найден в графе.
    """
    graph = get_compliance_graph()

    # Проверяем что узел существует
    risk_node = graph.get_node(risk_id)
    if risk_node is None:
        raise HTTPException(
            status_code=404,
            detail=f"Риск {risk_id!r} не найден в compliance-графе",
        )
    if risk_node.node_type != "risk":
        raise HTTPException(
            status_code=400,
            detail=f"Узел {risk_id!r} имеет тип {risk_node.node_type!r}, ожидался 'risk'",
        )

    affected = graph.propagate_risk(risk_id)
    return {
        "risk_id": risk_id,
        "risk": risk_node.to_dict(),
        "affected_controls": affected,
        "count": len(affected),
    }


# ── GET /api/graph/path ────────────────────────────────────────────────────────

@router.get(
    "/path",
    summary="Кратчайший путь между узлами",
    description=(
        "Возвращает BFS-кратчайший путь между двумя узлами графа. "
        "Путь учитывает направление рёбер."
    ),
)
def find_path(
    from_id: str = Query(..., description="ID начального узла"),
    to_id: str = Query(..., description="ID конечного узла"),
) -> dict[str, Any]:
    """
    Кратчайший путь между двумя узлами графа.

    Args:
        from_id: ID начального узла
        to_id:   ID конечного узла

    Returns:
        Словарь с path (список ID), nodes (объекты), length, found.

    Raises:
        404: если один из узлов не найден.
    """
    graph = get_compliance_graph()

    # Проверяем существование обоих узлов
    from_node = graph.get_node(from_id)
    to_node = graph.get_node(to_id)

    if from_node is None:
        raise HTTPException(
            status_code=404,
            detail=f"Начальный узел {from_id!r} не найден в графе",
        )
    if to_node is None:
        raise HTTPException(
            status_code=404,
            detail=f"Конечный узел {to_id!r} не найден в графе",
        )

    path = graph.find_path(from_id, to_id)
    # Обогащаем путь данными узлов
    path_nodes = [
        graph.get_node(nid).to_dict()
        for nid in path
        if graph.get_node(nid) is not None
    ]

    return {
        "from_id": from_id,
        "to_id": to_id,
        "path": path,
        "nodes": path_nodes,
        "length": len(path),
        "found": len(path) > 0,
    }


# ── GET /api/graph/vendor/{vendor_id}/controls ────────────────────────────────

@router.get(
    "/vendor/{vendor_id}/controls",
    summary="Контроли зависящие от вендора",
    description=(
        "Возвращает список контролей, которые косвенно зависят от вендора "
        "через цепочку: vendor ← owned_by ← risk ← has_risk ← control."
    ),
)
def get_vendor_controls(vendor_id: str) -> dict[str, Any]:
    """
    Какие контроли зависят от вендора.

    Args:
        vendor_id: идентификатор вендора (например, "VND-001")

    Returns:
        Словарь с vendor_id, vendor, affected_controls (список), count.

    Raises:
        404: если вендор не найден в графе.
    """
    graph = get_compliance_graph()

    vendor_node = graph.get_node(vendor_id)
    if vendor_node is None:
        raise HTTPException(
            status_code=404,
            detail=f"Вендор {vendor_id!r} не найден в compliance-графе",
        )
    if vendor_node.node_type != "vendor":
        raise HTTPException(
            status_code=400,
            detail=f"Узел {vendor_id!r} имеет тип {vendor_node.node_type!r}, ожидался 'vendor'",
        )

    affected = graph.find_affected_controls(vendor_id)
    return {
        "vendor_id": vendor_id,
        "vendor": vendor_node.to_dict(),
        "affected_controls": affected,
        "count": len(affected),
    }


# ── GET /api/graph/summary ────────────────────────────────────────────────────

@router.get(
    "/summary",
    summary="Статистика compliance-графа",
    description=(
        "Возвращает агрегированную статистику графа: "
        "количество узлов, рёбер, связанных компонент, "
        "распределение по типам."
    ),
)
def get_graph_summary() -> dict[str, Any]:
    """
    Статистика compliance-графа.

    Returns:
        Словарь с node_count, edge_count, connected_components,
        nodes_by_type, edges_by_type.
    """
    graph = get_compliance_graph()
    return graph.get_summary()


# ── POST /api/graph/rebuild ───────────────────────────────────────────────────

@router.post(
    "/rebuild",
    summary="Пересборка графа из файлов",
    description=(
        "Принудительно пересобирает compliance-граф из актуальных "
        "JSON-файлов (controls_map.json, risk_register.json, data/vendors.json). "
        "Сбрасывает кэш и возвращает новую статистику."
    ),
)
def rebuild_graph() -> dict[str, Any]:
    """
    Пересобрать граф из источников данных.

    Returns:
        Словарь со статистикой нового графа + статус операции.
    """
    log.info("GraphRoutes: запрос на пересборку compliance-графа")
    try:
        builder = get_graph_builder()
        graph = builder.rebuild()
        summary = graph.get_summary()
        log.info(
            "GraphRoutes: граф пересобран — узлов: %d, рёбер: %d",
            summary["node_count"],
            summary["edge_count"],
        )
        return {
            "status": "rebuilt",
            "summary": summary,
        }
    except Exception as exc:
        log.error("GraphRoutes: ошибка пересборки графа: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Ошибка пересборки графа: {exc}",
        )
