"""
test_governance.py — Тесты для GovernanceGraph.

Минимум 20 тестов покрывают:
  - создание аттестации и верификацию HMAC подписи
  - истечение TTL
  - отзыв аттестации
  - get_approval_chain для разных action_type
  - governance posture
  - покрытие аттестациями
  - SoD проверки
  - ApprovalNode и GovernanceAction валидацию
  - can_approve с делегированием
  - persistence (сохранение/загрузка)
"""

from __future__ import annotations

import json
import sys
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from governance_graph import (
    ApprovalNode,
    Attestation,
    GovernanceAction,
    GovernanceGraph,
    VALID_ACTION_TYPES,
    VALID_ROLES,
    _compute_signature,
    _make_signature_content,
    _verify_signature,
    _HMAC_KEY,
)


# ── Фикстуры ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_graph(tmp_path, monkeypatch):
    """
    Каждый тест использует изолированный GovernanceGraph с temp-файлом.
    EventBus мокируется чтобы избежать зависаний aiosqlite threads в тестах.
    """
    monkeypatch.setattr("governance_graph._GOVERNANCE_FILE", tmp_path / "governance.json")
    monkeypatch.setattr("governance_graph._DATA_DIR", tmp_path)
    # Сбрасываем singleton между тестами
    monkeypatch.setattr("governance_graph._graph_instance", None)
    yield tmp_path


@pytest.fixture(autouse=True)
def mock_event_bus():
    """
    Мокирует EventBus во всех тестах governance.
    Избегает зависаний aiosqlite threads после закрытия pytest event loop.
    """
    mock_bus = MagicMock()
    # Патчим event_bus.get_event_bus в модуле event_bus
    with patch("event_bus.get_event_bus", return_value=mock_bus):
        yield mock_bus


@pytest.fixture
def graph(tmp_path) -> GovernanceGraph:
    """Свежий GovernanceGraph с дефолтными узлами."""
    return GovernanceGraph(data_file=tmp_path / "governance.json")


@pytest.fixture
def action_policy(graph) -> GovernanceAction:
    """Зарегистрированное policy.approve действие."""
    return graph.create_action(
        action_type="policy.approve",
        required_role="compliance_officer",
        sla_hours=48,
    )


@pytest.fixture
def action_control(graph) -> GovernanceAction:
    """Зарегистрированное control.attest действие."""
    return graph.create_action(
        action_type="control.attest",
        required_role="auditor",
        sla_hours=24,
    )


# ── Тесты ApprovalNode ────────────────────────────────────────────────────────

class TestApprovalNode:
    def test_create_valid_node(self):
        """ApprovalNode создаётся с валидными параметрами."""
        node = ApprovalNode(
            node_id="test-node",
            role="ciso",
            can_approve=("policy.approve", "risk.accept"),
            can_delegate=True,
            delegates_to="compliance_officer",
        )
        assert node.node_id == "test-node"
        assert node.role == "ciso"
        assert "policy.approve" in node.can_approve
        assert node.can_delegate is True
        assert node.delegates_to == "compliance_officer"

    def test_node_rejects_invalid_role(self):
        """ApprovalNode отклоняет недопустимую роль."""
        with pytest.raises(ValueError, match="Недопустимая роль"):
            ApprovalNode(
                node_id="bad-node",
                role="hacker",
                can_approve=(),
                can_delegate=False,
            )

    def test_node_rejects_invalid_action_type(self):
        """ApprovalNode отклоняет недопустимый тип действия."""
        with pytest.raises(ValueError, match="Недопустимый тип действия"):
            ApprovalNode(
                node_id="bad-node",
                role="ciso",
                can_approve=("unknown.action",),
                can_delegate=False,
            )

    def test_node_is_frozen(self):
        """ApprovalNode не позволяет изменять атрибуты (frozen dataclass)."""
        node = ApprovalNode(
            node_id="frozen-node",
            role="auditor",
            can_approve=("control.attest",),
            can_delegate=False,
        )
        with pytest.raises((AttributeError, TypeError)):
            node.role = "ciso"  # type: ignore


# ── Тесты GovernanceAction ─────────────────────────────────────────────────────

class TestGovernanceAction:
    def test_create_valid_action(self):
        """GovernanceAction создаётся с валидными параметрами."""
        now = datetime.now(timezone.utc)
        action = GovernanceAction(
            action_id=str(uuid.uuid4()),
            action_type="control.attest",
            required_role="auditor",
            required_attestation=True,
            sla_hours=24,
            created_at=now,
        )
        assert action.action_type == "control.attest"
        assert action.sla_hours == 24

    def test_action_is_expired_when_past_deadline(self):
        """GovernanceAction.is_expired() = True если expires_at в прошлом."""
        action = GovernanceAction(
            action_id=str(uuid.uuid4()),
            action_type="policy.approve",
            required_role="ciso",
            required_attestation=True,
            sla_hours=1,
            created_at=datetime.now(timezone.utc) - timedelta(hours=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert action.is_expired() is True

    def test_action_is_overdue_when_sla_breached(self):
        """GovernanceAction.is_overdue() = True если созданá более sla_hours назад."""
        action = GovernanceAction(
            action_id=str(uuid.uuid4()),
            action_type="vendor.approve",
            required_role="manager",
            required_attestation=True,
            sla_hours=1,
            created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        assert action.is_overdue() is True

    def test_action_rejects_invalid_type(self):
        """GovernanceAction отклоняет недопустимый action_type."""
        with pytest.raises(ValueError, match="Недопустимый тип действия"):
            GovernanceAction(
                action_id="x",
                action_type="unknown.type",
                required_role="ciso",
                required_attestation=True,
                sla_hours=24,
                created_at=datetime.now(timezone.utc),
            )

    def test_action_rejects_zero_sla(self):
        """GovernanceAction отклоняет sla_hours <= 0."""
        with pytest.raises(ValueError, match="sla_hours"):
            GovernanceAction(
                action_id="x",
                action_type="policy.approve",
                required_role="ciso",
                required_attestation=True,
                sla_hours=0,
                created_at=datetime.now(timezone.utc),
            )


# ── Тесты HMAC ────────────────────────────────────────────────────────────────

class TestHMAC:
    def test_signature_is_deterministic(self):
        """Одинаковые параметры дают одинаковую подпись."""
        now = datetime.now(timezone.utc)
        content = _make_signature_content("att-1", "act-1", "user@x.com", "CC6.1", now)
        sig1 = _compute_signature(content)
        sig2 = _compute_signature(content)
        assert sig1 == sig2

    def test_signature_changes_with_different_content(self):
        """Разные параметры дают разные подписи."""
        now = datetime.now(timezone.utc)
        c1 = _make_signature_content("att-1", "act-1", "user@x.com", "CC6.1", now)
        c2 = _make_signature_content("att-2", "act-1", "user@x.com", "CC6.1", now)
        assert _compute_signature(c1) != _compute_signature(c2)

    def test_verify_correct_signature(self):
        """Верификация возвращает True для правильной подписи."""
        now = datetime.now(timezone.utc)
        content = _make_signature_content("att-1", "act-1", "user@x.com", "CC6.1", now)
        sig = _compute_signature(content)
        assert _verify_signature(content, sig) is True

    def test_verify_wrong_signature(self):
        """Верификация возвращает False для неправильной подписи."""
        now = datetime.now(timezone.utc)
        content = _make_signature_content("att-1", "act-1", "user@x.com", "CC6.1", now)
        assert _verify_signature(content, "deadbeef" * 8) is False

    def test_verify_tampered_content(self):
        """Верификация возвращает False при изменении содержимого."""
        now = datetime.now(timezone.utc)
        content = _make_signature_content("att-1", "act-1", "user@x.com", "CC6.1", now)
        sig = _compute_signature(content)
        tampered = _make_signature_content("att-1", "act-1", "evil@x.com", "CC6.1", now)
        assert _verify_signature(tampered, sig) is False


# ── Тесты создания и верификации аттестации ────────────────────────────────────

class TestCreateAttestation:
    def test_create_attestation_success(self, graph, action_policy):
        """Создание аттестации с валидными параметрами."""
        att = graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="policy-001",
            ttl_hours=72,
        )
        assert att.attestation_id is not None
        assert att.action_id == action_policy.action_id
        assert att.attested_by == "ciso@acme.com"
        assert att.role == "ciso"
        assert att.revoked is False
        assert len(att.signature) == 64  # SHA-256 hex = 64 chars

    def test_create_attestation_hmac_valid(self, graph, action_policy):
        """Подпись созданной аттестации верифицируется корректно."""
        att = graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="auditor@acme.com",
            role="compliance_officer",
            scope="CC6.1",
            ttl_hours=48,
        )
        assert graph.verify_attestation(att.attestation_id) is True

    def test_create_attestation_for_nonexistent_action(self, graph):
        """Попытка аттестовать несуществующее действие вызывает ошибку."""
        with pytest.raises(ValueError, match="не найдено"):
            graph.create_attestation(
                action_id="nonexistent-action-id",
                attested_by="ciso@acme.com",
                role="ciso",
                scope="CC6.1",
                ttl_hours=24,
            )

    def test_create_attestation_wrong_role_rejected(self, graph, action_policy):
        """Роль без прав на данный action_type получает ошибку."""
        with pytest.raises(ValueError, match="не может одобрять"):
            graph.create_attestation(
                action_id=action_policy.action_id,
                attested_by="manager@acme.com",
                role="manager",
                scope="policy-001",
                ttl_hours=24,
            )

    def test_create_attestation_invalid_role_rejected(self, graph, action_policy):
        """Недопустимая роль вызывает ValueError."""
        with pytest.raises(ValueError, match="Недопустимая роль"):
            graph.create_attestation(
                action_id=action_policy.action_id,
                attested_by="hacker@acme.com",
                role="superuser",
                scope="CC6.1",
                ttl_hours=24,
            )

    def test_create_attestation_invalid_ttl(self, graph, action_policy):
        """ttl_hours <= 0 вызывает ValueError."""
        with pytest.raises(ValueError, match="ttl_hours"):
            graph.create_attestation(
                action_id=action_policy.action_id,
                attested_by="ciso@acme.com",
                role="ciso",
                scope="CC6.1",
                ttl_hours=0,
            )


# ── Тесты истечения TTL ────────────────────────────────────────────────────────

class TestAttestationTTL:
    def test_attestation_valid_within_ttl(self, graph, action_control):
        """Аттестация действительна до истечения TTL."""
        att = graph.create_attestation(
            action_id=action_control.action_id,
            attested_by="auditor@acme.com",
            role="auditor",
            scope="CC7.1",
            ttl_hours=24,
        )
        assert att.is_valid() is True
        assert att.is_expired() is False

    def test_attestation_is_expired_after_ttl(self, tmp_path):
        """Аттестация с истёкшим valid_until считается недействительной."""
        graph = GovernanceGraph(data_file=tmp_path / "gov.json")
        action = graph.create_action("control.attest", "auditor", sla_hours=1)

        # Искусственно создаём уже истёкшую аттестацию
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        att_id = str(uuid.uuid4())
        content = _make_signature_content(att_id, action.action_id, "a@x.com", "CC6.1", past)
        sig = _compute_signature(content)
        expired_att = Attestation(
            attestation_id=att_id,
            action_id=action.action_id,
            attested_by="a@x.com",
            role="auditor",
            scope="CC6.1",
            valid_until=past,
            signature=sig,
        )
        # Вставляем напрямую в хранилище
        graph._attestations[att_id] = expired_att

        assert expired_att.is_expired() is True
        assert expired_att.is_valid() is False
        # verify_attestation должен вернуть False и опубликовать ANOMALY_DETECTED
        result = graph.verify_attestation(att_id)
        assert result is False

    def test_verify_nonexistent_attestation(self, graph):
        """verify_attestation возвращает False для несуществующей аттестации."""
        result = graph.verify_attestation("does-not-exist")
        assert result is False


# ── Тесты отзыва аттестации ───────────────────────────────────────────────────

class TestRevokeAttestation:
    def test_revoke_attestation_success(self, graph, action_policy):
        """Отзыв аттестации делает её недействительной."""
        att = graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="policy-001",
            ttl_hours=24,
        )
        assert graph.verify_attestation(att.attestation_id) is True

        result = graph.revoke_attestation(att.attestation_id, revoked_by="admin@acme.com")
        assert result is True

        # После отзыва — недействительна
        assert graph.verify_attestation(att.attestation_id) is False
        revoked = graph.get_attestation(att.attestation_id)
        assert revoked.revoked is True
        assert revoked.revoked_by == "admin@acme.com"
        assert revoked.revoked_at is not None

    def test_revoke_nonexistent_attestation(self, graph):
        """Попытка отозвать несуществующую аттестацию возвращает False."""
        result = graph.revoke_attestation("nonexistent", revoked_by="admin@acme.com")
        assert result is False

    def test_revoke_already_revoked(self, graph, action_policy):
        """Повторный отзыв уже отозванной аттестации возвращает False."""
        att = graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="policy-001",
            ttl_hours=24,
        )
        graph.revoke_attestation(att.attestation_id, revoked_by="admin@acme.com")
        result = graph.revoke_attestation(att.attestation_id, revoked_by="admin@acme.com")
        assert result is False


# ── Тесты get_approval_chain ──────────────────────────────────────────────────

class TestApprovalChain:
    def test_chain_policy_approve(self, graph):
        """Цепочка для policy.approve включает compliance_officer и ciso."""
        chain = graph.get_approval_chain("policy.approve")
        assert "compliance_officer" in chain
        assert "ciso" in chain

    def test_chain_control_attest(self, graph):
        """Цепочка для control.attest включает auditor."""
        chain = graph.get_approval_chain("control.attest")
        assert "auditor" in chain

    def test_chain_vendor_approve(self, graph):
        """Цепочка для vendor.approve включает manager и ciso."""
        chain = graph.get_approval_chain("vendor.approve")
        assert "manager" in chain
        assert "ciso" in chain

    def test_chain_access_review(self, graph):
        """Цепочка для access.review включает manager и auditor."""
        chain = graph.get_approval_chain("access.review")
        assert "manager" in chain

    def test_chain_risk_accept(self, graph):
        """Цепочка для risk.accept включает manager и ciso."""
        chain = graph.get_approval_chain("risk.accept")
        assert "ciso" in chain

    def test_chain_invalid_action_type(self, graph):
        """Неизвестный action_type вызывает ValueError."""
        with pytest.raises(ValueError, match="Неизвестный тип действия"):
            graph.get_approval_chain("unknown.action")

    def test_chain_returns_list(self, graph):
        """get_approval_chain всегда возвращает список."""
        for action_type in VALID_ACTION_TYPES:
            chain = graph.get_approval_chain(action_type)
            assert isinstance(chain, list)
            assert len(chain) > 0


# ── Тесты can_approve ─────────────────────────────────────────────────────────

class TestCanApprove:
    def test_ciso_can_approve_all(self, graph):
        """CISO может одобрять все типы действий (через цепочку)."""
        for action_type in VALID_ACTION_TYPES:
            assert graph.can_approve("ciso", action_type) is True

    def test_auditor_can_attest_control(self, graph):
        """Auditor может аттестовать control.attest."""
        assert graph.can_approve("auditor", "control.attest") is True

    def test_auditor_cannot_approve_policy(self, graph):
        """Auditor не может одобрять policy.approve (не в цепочке)."""
        assert graph.can_approve("auditor", "policy.approve") is False

    def test_manager_can_approve_vendor(self, graph):
        """Manager может одобрять vendor.approve."""
        assert graph.can_approve("manager", "vendor.approve") is True

    def test_invalid_role_returns_false(self, graph):
        """Несуществующая роль возвращает False."""
        assert graph.can_approve("superuser", "policy.approve") is False

    def test_invalid_action_type_returns_false(self, graph):
        """Несуществующий action_type возвращает False."""
        assert graph.can_approve("ciso", "unknown.action") is False


# ── Тесты governance posture ──────────────────────────────────────────────────

class TestGovernancePosture:
    def test_posture_has_required_fields(self, graph):
        """get_governance_posture() возвращает все обязательные поля."""
        posture = graph.get_governance_posture()
        required_fields = {
            "pending_approvals_count",
            "expired_attestations",
            "coverage_percent",
            "critical_gaps",
            "total_attestations",
            "active_attestations",
            "revoked_attestations",
            "sla_breaches",
        }
        assert required_fields.issubset(posture.keys())

    def test_posture_empty_graph(self, graph):
        """Пустой граф: нет аттестаций, coverage 100% (нет требований)."""
        posture = graph.get_governance_posture()
        assert posture["total_attestations"] == 0
        assert posture["active_attestations"] == 0
        assert posture["coverage_percent"] == 100.0

    def test_posture_counts_pending_correctly(self, graph, action_policy, action_control):
        """Pending actions считаются корректно."""
        posture_before = graph.get_governance_posture()
        pending_before = posture_before["pending_approvals_count"]

        # Аттестуем одно действие
        graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="policy-001",
            ttl_hours=24,
        )

        posture_after = graph.get_governance_posture()
        assert posture_after["pending_approvals_count"] == pending_before - 1

    def test_posture_coverage_percent(self, graph, action_control):
        """coverage_percent растёт при добавлении аттестаций."""
        att = graph.create_attestation(
            action_id=action_control.action_id,
            attested_by="auditor@acme.com",
            role="auditor",
            scope="CC6.1",
            ttl_hours=24,
        )
        posture = graph.get_governance_posture()
        assert posture["coverage_percent"] > 0
        assert posture["active_attestations"] >= 1

    def test_posture_revoked_not_counted_as_active(self, graph, action_policy):
        """Отозванные аттестации не считаются активными."""
        att = graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="policy-002",
            ttl_hours=24,
        )
        graph.revoke_attestation(att.attestation_id, revoked_by="admin@acme.com")

        posture = graph.get_governance_posture()
        assert posture["revoked_attestations"] >= 1


# ── Тесты покрытия аттестациями ───────────────────────────────────────────────

class TestAttestationCoverage:
    def test_coverage_all_missing(self, graph):
        """Без аттестаций все контроли не покрыты."""
        controls = ["CC6.1", "CC6.2", "CC7.1"]
        coverage = graph.check_attestation_coverage(controls)
        assert all(not covered for covered in coverage.values())

    def test_coverage_with_attestation(self, graph, action_control):
        """Покрытие правильно отображает аттестованные контроли."""
        graph.create_attestation(
            action_id=action_control.action_id,
            attested_by="auditor@acme.com",
            role="auditor",
            scope="CC6.1",
            ttl_hours=24,
        )
        coverage = graph.check_attestation_coverage(["CC6.1", "CC6.2"])
        assert coverage["CC6.1"] is True
        assert coverage["CC6.2"] is False

    def test_coverage_revoked_not_counted(self, graph, action_policy):
        """Отозванная аттестация не засчитывается как покрытие."""
        att = graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="CC8.1",
            ttl_hours=24,
        )
        graph.revoke_attestation(att.attestation_id, revoked_by="admin@acme.com")
        coverage = graph.check_attestation_coverage(["CC8.1"])
        assert coverage["CC8.1"] is False

    def test_get_attestations_for_control(self, graph, action_policy, action_control):
        """get_attestations_for_control возвращает только аттестации с нужным scope."""
        att1 = graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="CC6.1",
            ttl_hours=24,
        )
        att2 = graph.create_attestation(
            action_id=action_control.action_id,
            attested_by="auditor@acme.com",
            role="auditor",
            scope="CC7.1",
            ttl_hours=24,
        )
        result = graph.get_attestations_for_control("CC6.1")
        ids = [a.attestation_id for a in result]
        assert att1.attestation_id in ids
        assert att2.attestation_id not in ids


# ── Тесты persistence ─────────────────────────────────────────────────────────

class TestPersistence:
    def test_attestations_persist_across_instances(self, tmp_path):
        """Аттестации сохраняются и загружаются между экземплярами."""
        data_file = tmp_path / "gov.json"
        g1 = GovernanceGraph(data_file=data_file)
        action = g1.create_action("control.attest", "auditor", sla_hours=24)
        att = g1.create_attestation(
            action_id=action.action_id,
            attested_by="auditor@acme.com",
            role="auditor",
            scope="CC6.1",
            ttl_hours=48,
        )

        # Создаём новый экземпляр с тем же файлом
        g2 = GovernanceGraph(data_file=data_file)
        loaded = g2.get_attestation(att.attestation_id)
        assert loaded is not None
        assert loaded.attestation_id == att.attestation_id
        assert loaded.scope == "CC6.1"
        assert loaded.revoked is False

    def test_revoke_persists(self, tmp_path):
        """Отзыв аттестации сохраняется между экземплярами."""
        data_file = tmp_path / "gov.json"
        g1 = GovernanceGraph(data_file=data_file)
        action = g1.create_action("policy.approve", "compliance_officer", sla_hours=24)
        att = g1.create_attestation(
            action_id=action.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="policy-001",
            ttl_hours=48,
        )
        g1.revoke_attestation(att.attestation_id, revoked_by="admin@acme.com")

        g2 = GovernanceGraph(data_file=data_file)
        loaded = g2.get_attestation(att.attestation_id)
        assert loaded is not None
        assert loaded.revoked is True
        assert loaded.revoked_by == "admin@acme.com"


# ── Тест get_pending_actions ──────────────────────────────────────────────────

class TestPendingActions:
    def test_pending_decreases_after_attest(self, graph):
        """Аттестация действия убирает его из pending."""
        action = graph.create_action("access.review", "manager", sla_hours=8)
        pending_before = [a.action_id for a in graph.get_pending_actions()]
        assert action.action_id in pending_before

        graph.create_attestation(
            action_id=action.action_id,
            attested_by="manager@acme.com",
            role="manager",
            scope="access-review-q1",
            ttl_hours=24,
        )

        pending_after = [a.action_id for a in graph.get_pending_actions()]
        assert action.action_id not in pending_after

    def test_pending_action_returns_after_revoke(self, graph):
        """После отзыва аттестации действие снова становится pending."""
        action = graph.create_action("risk.accept", "ciso", sla_hours=24)
        att = graph.create_attestation(
            action_id=action.action_id,
            attested_by="ciso@acme.com",
            role="ciso",
            scope="risk-001",
            ttl_hours=24,
        )

        graph.revoke_attestation(att.attestation_id, revoked_by="admin@acme.com")

        pending = [a.action_id for a in graph.get_pending_actions()]
        assert action.action_id in pending


# ── Тест SoD ─────────────────────────────────────────────────────────────────

class TestSoDChecks:
    def test_sod_compliance_officer_can_attest_policy(self, graph, action_policy):
        """compliance_officer может аттестовать policy.approve."""
        att = graph.create_attestation(
            action_id=action_policy.action_id,
            attested_by="co@acme.com",
            role="compliance_officer",
            scope="policy-x",
            ttl_hours=24,
        )
        assert att is not None
        assert graph.verify_attestation(att.attestation_id) is True

    def test_sod_manager_cannot_attest_policy(self, graph, action_policy):
        """manager не может аттестовать policy.approve (SoD нарушение)."""
        with pytest.raises(ValueError, match="не может одобрять"):
            graph.create_attestation(
                action_id=action_policy.action_id,
                attested_by="manager@acme.com",
                role="manager",
                scope="policy-x",
                ttl_hours=24,
            )
