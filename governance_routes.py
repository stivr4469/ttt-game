"""
governance_routes.py — FastAPI роуты для Governance Graph.

Префикс: /api/governance

Эндпоинты:
  GET  /api/governance/posture                      — общее состояние governance
  GET  /api/governance/pending                      — список pending approvals
  POST /api/governance/attest                       — создать аттестацию
  GET  /api/governance/attestations/{control_id}    — аттестации для контроля
  POST /api/governance/attest/{attestation_id}/revoke — отозвать аттестацию
  GET  /api/governance/can-approve                  — проверка прав (role, action_type)
  GET  /api/governance/chain/{action_type}          — цепочка одобрения
  GET  /api/governance/nodes                        — список участников
  POST /api/governance/actions                      — создать governance action

Авторизация: require_auth для чтения, require_admin для записи.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from auth import require_auth, require_admin
from governance_graph import (
    ApprovalNode,
    GovernanceAction,
    VALID_ACTION_TYPES,
    VALID_ROLES,
    get_governance_graph,
)
from log_config import get_logger

log = get_logger(__name__)

router = APIRouter(prefix="/api/governance", tags=["governance"])


# ── Pydantic-схемы ─────────────────────────────────────────────────────────────

class AttestRequest(BaseModel):
    """Запрос на создание аттестации."""
    action_id:  str = Field(..., min_length=1, description="ID governance действия")
    scope:      str = Field(..., min_length=1, description="Что аттестуется (control_id, policy_id, etc.)")
    ttl_hours:  int = Field(default=8760, ge=1, le=87600, description="Время жизни аттестации (часы, 1–87600)")


class RevokeRequest(BaseModel):
    """Запрос на отзыв аттестации."""
    revoked_by: str = Field(..., min_length=1, description="Кто отзывает (email или role)")


class CreateActionRequest(BaseModel):
    """Запрос на создание governance действия."""
    action_type:          str = Field(..., description=f"Тип действия: {sorted(VALID_ACTION_TYPES)}")
    required_role:        str = Field(..., description=f"Требуемая роль: {sorted(VALID_ROLES)}")
    sla_hours:            int = Field(default=24, ge=1, le=8760, description="SLA в часах")
    required_attestation: bool = Field(default=True, description="Требуется ли аттестация")


# ── Хелперы сериализации ───────────────────────────────────────────────────────

def _serialize_node(node: ApprovalNode) -> Dict[str, Any]:
    return {
        "node_id":      node.node_id,
        "role":         node.role,
        "can_approve":  list(node.can_approve),
        "can_delegate": node.can_delegate,
        "delegates_to": node.delegates_to,
    }


def _serialize_action(action: GovernanceAction) -> Dict[str, Any]:
    return {
        "action_id":            action.action_id,
        "action_type":          action.action_type,
        "required_role":        action.required_role,
        "required_attestation": action.required_attestation,
        "sla_hours":            action.sla_hours,
        "created_at":           action.created_at.isoformat() if action.created_at else None,
        "expires_at":           action.expires_at.isoformat() if action.expires_at else None,
        "is_expired":           action.is_expired(),
        "is_overdue":           action.is_overdue(),
    }


def _serialize_attestation(a) -> Dict[str, Any]:
    return {
        "attestation_id": a.attestation_id,
        "action_id":      a.action_id,
        "attested_by":    a.attested_by,
        "role":           a.role,
        "scope":          a.scope,
        "valid_until":    a.valid_until.isoformat() if a.valid_until else None,
        "signature":      a.signature,
        "revoked":        a.revoked,
        "revoked_by":     a.revoked_by,
        "revoked_at":     a.revoked_at.isoformat() if a.revoked_at else None,
        "created_at":     a.created_at.isoformat() if a.created_at else None,
        "is_valid":       a.is_valid(),
        "is_expired":     a.is_expired(),
    }


# ── Эндпоинты ─────────────────────────────────────────────────────────────────

@router.get("/posture")
async def get_governance_posture(
    user: dict = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Возвращает общее состояние governance.

    Поля ответа:
      pending_approvals_count — незакрытые действия
      expired_attestations    — ID истёкших аттестаций
      coverage_percent        — % охвата аттестациями
      critical_gaps           — контроли без аттестации
      total_attestations      — всего аттестаций
      active_attestations     — действующих аттестаций
      revoked_attestations    — отозванных аттестаций
      sla_breaches            — просроченные SLA
    """
    graph = get_governance_graph()
    return graph.get_governance_posture()


@router.get("/pending")
async def get_pending_actions(
    user: dict = Depends(require_auth),
) -> List[Dict[str, Any]]:
    """
    Возвращает список незакрытых governance действий.

    Действие считается незакрытым если для него нет
    действительной (не отозванной, не истёкшей) аттестации.
    """
    graph = get_governance_graph()
    actions = graph.get_pending_actions()
    return [_serialize_action(a) for a in actions]


@router.post("/attest")
async def create_attestation(
    body: AttestRequest,
    user: dict = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Создаёт аттестацию для governance действия.

    Роль определяется из JWT токена аутентифицированного пользователя.
    SoD: нельзя аттестовать если роль не входит в цепочку одобрения.

    Body:
      action_id  — ID действия GovernanceAction
      scope      — что аттестуется (control_id, policy_id, etc.)
      ttl_hours  — время жизни аттестации в часах
    """
    graph = get_governance_graph()

    attested_by = user.get("email") or user.get("sub") or "unknown"
    # Маппим системные роли auth.py в governance роли
    system_role = user.get("role", "viewer")
    governance_role = _map_auth_role(system_role)

    if governance_role is None:
        raise HTTPException(
            status_code=403,
            detail=f"Роль '{system_role}' не имеет прав governance. "
                   f"Требуется одна из: {sorted(VALID_ROLES)}",
        )

    try:
        attestation = graph.create_attestation(
            action_id=body.action_id,
            attested_by=attested_by,
            role=governance_role,
            scope=body.scope,
            ttl_hours=body.ttl_hours,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    log.info(
        "governance_routes: аттестация создана",
        extra={
            "attestation_id": attestation.attestation_id,
            "attested_by":    attested_by,
            "role":           governance_role,
        },
    )
    return _serialize_attestation(attestation)


@router.get("/attestations/{control_id}")
async def get_attestations_for_control(
    control_id: str,
    user: dict = Depends(require_auth),
) -> List[Dict[str, Any]]:
    """
    Возвращает все аттестации для данного контроля.

    Ищет по scope (control_id должен быть частью scope).
    Включает отозванные и истёкшие — для полного аудит трейла.
    """
    graph = get_governance_graph()
    attestations = graph.get_attestations_for_control(control_id)
    return [_serialize_attestation(a) for a in attestations]


@router.post("/attest/{attestation_id}/revoke")
async def revoke_attestation(
    attestation_id: str,
    body: RevokeRequest,
    user: dict = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Отзывает аттестацию.

    Только admin может отзывать аттестации.
    Отзыв необратим (append-only): аттестация остаётся в истории с revoked=True.

    Body:
      revoked_by — кто отзывает (email или role)
    """
    graph = get_governance_graph()
    success = graph.revoke_attestation(
        attestation_id=attestation_id,
        revoked_by=body.revoked_by,
    )
    if not success:
        raise HTTPException(
            status_code=404,
            detail=f"Аттестация '{attestation_id}' не найдена или уже отозвана",
        )

    attestation = graph.get_attestation(attestation_id)
    return {
        "success":        True,
        "attestation_id": attestation_id,
        "revoked_by":     body.revoked_by,
        "attestation":    _serialize_attestation(attestation) if attestation else None,
    }


@router.get("/can-approve")
async def check_can_approve(
    role:        str = Query(..., description=f"Роль: {sorted(VALID_ROLES)}"),
    action_type: str = Query(..., description=f"Тип действия: {sorted(VALID_ACTION_TYPES)}"),
    user: dict = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Проверяет может ли роль одобрять указанный тип действия.

    Query params:
      role        — governance роль (ciso | manager | auditor | compliance_officer)
      action_type — тип действия (policy.approve | control.attest | ...)
    """
    if role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Неверная роль: '{role}'. Допустимые: {sorted(VALID_ROLES)}",
        )
    if action_type not in VALID_ACTION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Неверный тип действия: '{action_type}'. Допустимые: {sorted(VALID_ACTION_TYPES)}",
        )

    graph = get_governance_graph()
    allowed = graph.can_approve(role=role, action_type=action_type)
    return {
        "role":        role,
        "action_type": action_type,
        "can_approve": allowed,
    }


@router.get("/chain/{action_type}")
async def get_approval_chain(
    action_type: str,
    user: dict = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Возвращает цепочку одобрения для типа действия.

    Цепочка — упорядоченный список ролей от инициатора к финальному одобряющему.
    """
    if action_type not in VALID_ACTION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Неверный тип действия: '{action_type}'. Допустимые: {sorted(VALID_ACTION_TYPES)}",
        )

    graph = get_governance_graph()
    try:
        chain = graph.get_approval_chain(action_type)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "action_type":     action_type,
        "approval_chain":  chain,
        "chain_length":    len(chain),
    }


@router.get("/nodes")
async def list_approval_nodes(
    user: dict = Depends(require_auth),
) -> List[Dict[str, Any]]:
    """
    Возвращает список всех зарегистрированных участников governance.
    """
    graph = get_governance_graph()
    return [_serialize_node(n) for n in graph.list_nodes()]


@router.post("/actions")
async def create_governance_action(
    body: CreateActionRequest,
    user: dict = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Создаёт новое governance действие.

    Только admin может создавать governance действия.
    После создания публикует событие в EventBus.

    Body:
      action_type          — тип действия
      required_role        — минимальная роль для одобрения
      sla_hours            — SLA в часах (default: 24)
      required_attestation — требуется ли аттестация (default: true)
    """
    if body.action_type not in VALID_ACTION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Неверный тип действия: '{body.action_type}'. Допустимые: {sorted(VALID_ACTION_TYPES)}",
        )
    if body.required_role not in VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Неверная роль: '{body.required_role}'. Допустимые: {sorted(VALID_ROLES)}",
        )

    graph = get_governance_graph()
    action = graph.create_action(
        action_type=body.action_type,
        required_role=body.required_role,
        sla_hours=body.sla_hours,
        required_attestation=body.required_attestation,
    )

    log.info(
        "governance_routes: создано governance действие",
        extra={"action_id": action.action_id, "action_type": action.action_type},
    )
    return _serialize_action(action)


@router.get("/coverage")
async def check_coverage(
    controls: str = Query(..., description="Список control_id через запятую, например: CC6.1,CC6.2,CC7.1"),
    user: dict = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Проверяет покрытие аттестациями для списка контролей.

    Query param:
      controls — control_id через запятую (CC6.1,CC6.2,CC7.1)

    Возвращает:
      coverage — Dict[control_id, bool]
      covered  — список покрытых контролей
      missing  — список не покрытых контролей
    """
    control_list = [c.strip() for c in controls.split(",") if c.strip()]
    if not control_list:
        raise HTTPException(status_code=400, detail="Список контролей не может быть пустым")

    graph = get_governance_graph()
    coverage = graph.check_attestation_coverage(control_list)

    covered = [c for c, has in coverage.items() if has]
    missing = [c for c, has in coverage.items() if not has]

    return {
        "coverage": coverage,
        "covered":  covered,
        "missing":  missing,
        "coverage_percent": round(len(covered) / len(control_list) * 100, 1) if control_list else 100.0,
    }


@router.get("/verify/{attestation_id}")
async def verify_attestation(
    attestation_id: str,
    user: dict = Depends(require_auth),
) -> Dict[str, Any]:
    """
    Верифицирует аттестацию: HMAC подпись + срок действия + revoke.

    Returns:
      valid     — True если аттестация действительна
      details   — детали аттестации
    """
    graph = get_governance_graph()
    valid = graph.verify_attestation(attestation_id)
    attestation = graph.get_attestation(attestation_id)

    if attestation is None:
        raise HTTPException(
            status_code=404,
            detail=f"Аттестация '{attestation_id}' не найдена",
        )

    return {
        "valid":       valid,
        "attestation": _serialize_attestation(attestation),
    }


# ── Утилита маппинга ролей ─────────────────────────────────────────────────────

def _map_auth_role(system_role: str) -> Optional[str]:
    """
    Маппит системную роль из auth.py в governance роль.

    Маппинг:
      admin   → ciso (наивысшие полномочия)
      auditor → auditor
      scanner → compliance_officer
      viewer  → None (нет governance прав)
    """
    mapping = {
        "admin":   "ciso",
        "Admin":   "ciso",
        "auditor": "auditor",
        "Auditor": "auditor",
        "scanner": "compliance_officer",
        "Scanner": "compliance_officer",
    }
    return mapping.get(system_role)
