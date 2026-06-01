"""
Тесты PolicyLifecycleManager — SoD workflow для SOC2 политик.

Минимум 12 тестов покрывают весь жизненный цикл:
  draft → pending_review → approved/rejected → draft (revise)
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from policy_lifecycle import PolicyLifecycleManager, PolicyStatus


# ── Фикстуры ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_storage(monkeypatch):
    """Каждый тест получает изолированное in-memory хранилище.

    _load_policies/_save_policies — единственные точки доступа к данным в
    PolicyLifecycleManager, поэтому мок достаточен для проверки бизнес-логики
    без поднятия реальной БД.
    """
    _store: list[dict] = []

    def _mock_load() -> list[dict]:
        return list(_store)

    def _mock_save(records: list[dict]) -> None:
        _store.clear()
        _store.extend(records)

    monkeypatch.setattr("policy_lifecycle._load_policies", _mock_load)
    monkeypatch.setattr("policy_lifecycle._save_policies", _mock_save)
    yield _store


@pytest.fixture
def manager():
    return PolicyLifecycleManager()


@pytest.fixture
def draft_record(manager):
    """Готовый черновик для использования в тестах."""
    return manager.create_draft(
        control_id="ctrl-001",
        control_code="CC6.1",
        title="Access Control Policy",
        content="All access must be authenticated and authorized.",
        created_by="ai:claude-haiku-4-5",
    )


@pytest.fixture
def pending_record(manager, draft_record):
    """Черновик, поданный на ревью."""
    return manager.submit_for_review(draft_record.id)


# ── Тесты создания черновика ──────────────────────────────────────────────────

class TestCreateDraft:
    def test_create_draft_sets_status_draft(self, manager):
        """Новый черновик всегда имеет статус DRAFT."""
        record = manager.create_draft(
            control_id="ctrl-002",
            control_code="CC7.2",
            title="Incident Response Policy",
            content="Incidents must be reported within 24 hours.",
            created_by="ai:claude-haiku-4-5",
        )
        assert record.status == PolicyStatus.DRAFT

    def test_create_draft_created_by_ai(self, manager):
        """Поле created_by отражает AI-агента, который создал черновик."""
        record = manager.create_draft(
            control_id="ctrl-003",
            control_code="CC8.1",
            title="Change Management Policy",
            content="All changes must go through the change control process.",
            created_by="ai:claude-haiku-4-5-20251001",
        )
        assert record.created_by.startswith("ai:")
        assert "claude" in record.created_by

    def test_create_draft_generates_unique_id(self, manager):
        """Каждый черновик получает уникальный ID с префиксом POL-."""
        r1 = manager.create_draft("c1", "CC1.1", "Policy A", "Content A", "ai:model")
        r2 = manager.create_draft("c2", "CC1.2", "Policy B", "Content B", "ai:model")
        assert r1.id != r2.id
        assert r1.id.startswith("POL-")
        assert r2.id.startswith("POL-")

    def test_create_draft_version_is_one(self, manager):
        """Начальная версия черновика — 1."""
        record = manager.create_draft("c1", "CC1.1", "T", "C", "ai:model")
        assert record.version == 1

    def test_create_draft_approved_at_is_none(self, manager):
        """Черновик не имеет даты одобрения."""
        record = manager.create_draft("c1", "CC1.1", "T", "C", "ai:model")
        assert record.approved_at is None
        assert record.approved_by is None


# ── Тест перевода в pending_review ────────────────────────────────────────────

class TestSubmitForReview:
    def test_submit_for_review_changes_status(self, manager, draft_record):
        """Подача на ревью меняет статус draft → pending_review."""
        record = manager.submit_for_review(draft_record.id)
        assert record.status == PolicyStatus.PENDING_REVIEW

    def test_submit_non_draft_raises(self, manager, pending_record):
        """Нельзя подать на ревью уже поданную политику."""
        with pytest.raises(ValueError, match="draft"):
            manager.submit_for_review(pending_record.id)


# ── Тесты approve ─────────────────────────────────────────────────────────────

class TestApprove:
    def test_approve_sets_approved_status(self, manager, pending_record):
        """После approve статус становится APPROVED."""
        with patch("policy_lifecycle.PolicyLifecycleManager._update_control_status"):
            record = manager.approve(pending_record.id, approver="admin@acme.com")
        assert record.status == PolicyStatus.APPROVED

    def test_approve_increments_version(self, manager, pending_record):
        """Каждый approve инкрементирует версию."""
        with patch("policy_lifecycle.PolicyLifecycleManager._update_control_status"):
            record = manager.approve(pending_record.id, approver="admin@acme.com")
        assert record.version == 2

    def test_approve_sets_approved_at(self, manager, pending_record):
        """После approve устанавливается дата и автор одобрения."""
        with patch("policy_lifecycle.PolicyLifecycleManager._update_control_status"):
            record = manager.approve(pending_record.id, approver="admin@acme.com")
        assert record.approved_at is not None
        assert record.approved_by == "admin@acme.com"

    def test_cannot_approve_draft_directly(self, manager, draft_record):
        """Нельзя одобрить черновик напрямую — должен быть pending_review."""
        with pytest.raises(ValueError, match="pending_review"):
            manager.approve(draft_record.id, approver="admin@acme.com")

    def test_approve_calls_update_control_status(self, manager, pending_record):
        """Approve вызывает EvidenceClient.update_control_status с PASS."""
        with patch.object(manager, "_update_control_status") as mock_update:
            manager.approve(pending_record.id, approver="admin@acme.com")
        mock_update.assert_called_once_with(
            pending_record.control_id, "PASS", pending_record.id
        )


# ── Тесты reject ──────────────────────────────────────────────────────────────

class TestReject:
    def test_reject_sets_rejected_status(self, manager, pending_record):
        """После reject статус становится REJECTED."""
        record = manager.reject(pending_record.id, reviewer="auditor@acme.com", reason="Missing scope")
        assert record.status == PolicyStatus.REJECTED

    def test_reject_stores_reason(self, manager, pending_record):
        """Причина отклонения сохраняется в поле rejection_reason."""
        reason = "Policy scope is too broad and needs clarification"
        record = manager.reject(pending_record.id, reviewer="auditor@acme.com", reason=reason)
        assert record.rejection_reason == reason
        assert record.rejected_by == "auditor@acme.com"

    def test_reject_empty_reason_raises(self, manager, pending_record):
        """Пустая причина отклонения недопустима."""
        with pytest.raises(ValueError, match="пустой"):
            manager.reject(pending_record.id, reviewer="auditor@acme.com", reason="")


# ── Тест revise ───────────────────────────────────────────────────────────────

class TestRevise:
    def test_revise_resets_to_draft(self, manager, pending_record):
        """После revise отклонённой политики статус возвращается в draft."""
        rejected = manager.reject(pending_record.id, reviewer="auditor@acme.com", reason="Too vague")
        revised = manager.revise(rejected.id, new_content="Updated and more specific content.", editor="human:auditor@acme.com")
        assert revised.status == PolicyStatus.DRAFT

    def test_revise_updates_content(self, manager, pending_record):
        """revise заменяет content новым текстом."""
        manager.reject(pending_record.id, reviewer="aud", reason="Bad")
        new_content = "Completely rewritten policy content."
        record = manager.revise(pending_record.id, new_content=new_content, editor="human:admin@acme.com")
        assert record.content == new_content

    def test_revise_non_rejected_raises(self, manager, draft_record):
        """Нельзя revise черновик — только rejected."""
        with pytest.raises(ValueError, match="rejected"):
            manager.revise(draft_record.id, new_content="new text", editor="human:admin@acme.com")

    def test_revise_clears_rejection_fields(self, manager, pending_record):
        """После revise поля rejected_by и rejection_reason очищаются."""
        manager.reject(pending_record.id, reviewer="aud", reason="Needs work")
        record = manager.revise(pending_record.id, new_content="Better content.", editor="human:admin@acme.com")
        assert record.rejected_by is None
        assert record.rejection_reason is None


# ── Тесты статистики ──────────────────────────────────────────────────────────

class TestStatistics:
    def test_get_pending_count(self, manager):
        """get_pending_count возвращает точное число политик в pending_review."""
        r1 = manager.create_draft("c1", "CC1.1", "T1", "C1", "ai:m")
        r2 = manager.create_draft("c2", "CC1.2", "T2", "C2", "ai:m")
        manager.create_draft("c3", "CC1.3", "T3", "C3", "ai:m")

        manager.submit_for_review(r1.id)
        manager.submit_for_review(r2.id)

        assert manager.get_pending_count() == 2

    def test_get_summary_counts(self, manager):
        """get_summary корректно считает политики по каждому статусу."""
        r1 = manager.create_draft("c1", "CC1.1", "T1", "C1", "ai:m")
        r2 = manager.create_draft("c2", "CC1.2", "T2", "C2", "ai:m")
        r3 = manager.create_draft("c3", "CC1.3", "T3", "C3", "ai:m")

        manager.submit_for_review(r1.id)
        with patch("policy_lifecycle.PolicyLifecycleManager._update_control_status"):
            manager.approve(r1.id, approver="admin@acme.com")

        pending = manager.submit_for_review(r2.id)
        manager.reject(pending.id, reviewer="aud", reason="Needs work")

        summary = manager.get_summary()
        assert summary["total"] == 3
        assert summary["by_status"]["approved"] == 1
        assert summary["by_status"]["rejected"] == 1
        assert summary["by_status"]["draft"] == 1
        assert summary["by_status"]["pending_review"] == 0


# ── Тест get_all с фильтрами ──────────────────────────────────────────────────

class TestGetAll:
    def test_get_all_filter_by_status(self, manager):
        """Фильтр по статусу возвращает только подходящие записи."""
        manager.create_draft("c1", "CC1.1", "T1", "C1", "ai:m")
        r2 = manager.create_draft("c2", "CC1.2", "T2", "C2", "ai:m")
        manager.submit_for_review(r2.id)

        drafts = manager.get_all(status="draft")
        assert len(drafts) == 1
        assert drafts[0].control_code == "CC1.1"

    def test_get_all_filter_by_control_code(self, manager):
        """Фильтр по коду контрола возвращает только нужные политики."""
        manager.create_draft("c1", "CC6.1", "T1", "C1", "ai:m")
        manager.create_draft("c2", "CC7.2", "T2", "C2", "ai:m")
        manager.create_draft("c3", "CC6.1", "T3", "C3", "ai:m")

        cc61 = manager.get_all(control_code="CC6.1")
        assert len(cc61) == 2
        assert all(r.control_code == "CC6.1" for r in cc61)


# ── Тест персистентности ──────────────────────────────────────────────────────

class TestPersistence:
    def test_records_persisted_to_store(self, manager, isolated_storage):
        """Черновик сохраняется в хранилище (store)."""
        manager.create_draft("c1", "CC1.1", "Title", "Content", "ai:model")
        assert len(isolated_storage) == 1
        assert isolated_storage[0]["status"] == "draft"

    def test_new_manager_reads_existing_data(self, manager, isolated_storage):
        """Новый экземпляр менеджера читает данные из того же store."""
        manager.create_draft("c1", "CC1.1", "Title", "Content", "ai:model")
        new_manager = PolicyLifecycleManager()
        records = new_manager.get_all()
        assert len(records) == 1
        assert records[0].control_code == "CC1.1"
