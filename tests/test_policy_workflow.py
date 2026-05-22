"""
Тесты для policy_workflow.py (PolicyWorkflow).
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch, MagicMock
from policy_workflow import PolicyWorkflow


@pytest.fixture
def wf(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("policy_workflow.EvidenceClient"):
        return PolicyWorkflow()


# ─── Вспомогательная фикстура: создать и отправить на согласование ────────────

def _make_draft(wf: PolicyWorkflow, code="CC6.1", v_suffix="") -> dict:
    return wf.create_draft(
        control_code=code,
        title=f"Тестовая политика{v_suffix}",
        content="Содержимое политики",
        created_by="author@acme.com",
        change_summary="Начальная версия",
    )


def _submit(wf: PolicyWorkflow, code="CC6.1", version=1) -> dict:
    return wf.submit_for_approval(code, version)


# ══════════════════════════════════════════════════════════════════════════════
# TestCreateDraft
# ══════════════════════════════════════════════════════════════════════════════

class TestCreateDraft:
    def test_status_is_draft(self, wf):
        result = _make_draft(wf)
        assert result["status"] == "draft"

    def test_version_starts_at_one(self, wf):
        result = _make_draft(wf)
        assert result["version"] == 1

    def test_control_code_in_result(self, wf):
        result = _make_draft(wf, code="CC7.2")
        assert result["control_code"] == "CC7.2"

    def test_saved_to_file(self, wf, tmp_path):
        _make_draft(wf)
        assert (tmp_path / "policy_versions.json").exists()

    def test_second_draft_increments_to_v2(self, wf):
        _make_draft(wf)
        result2 = _make_draft(wf)
        assert result2["version"] == 2

    def test_third_draft_is_v3(self, wf):
        for _ in range(3):
            result = _make_draft(wf)
        assert result["version"] == 3

    def test_different_controls_independent_versions(self, wf):
        r1 = _make_draft(wf, code="CC6.1")
        r2 = _make_draft(wf, code="CC6.2")
        assert r1["version"] == 1
        assert r2["version"] == 1

    def test_history_contains_created_draft(self, wf):
        _make_draft(wf, code="CC6.1")
        history = wf.get_history("CC6.1")
        assert len(history) == 1
        assert history[0]["status"] == "draft"


# ══════════════════════════════════════════════════════════════════════════════
# TestSubmitForApproval
# ══════════════════════════════════════════════════════════════════════════════

class TestSubmitForApproval:
    def test_draft_to_pending_approval(self, wf):
        _make_draft(wf)
        result = _submit(wf)
        assert result["status"] == "pending_approval"

    def test_submit_returns_control_code(self, wf):
        _make_draft(wf)
        result = _submit(wf)
        assert result["control_code"] == "CC6.1"

    def test_non_draft_returns_error(self, wf):
        _make_draft(wf)
        _submit(wf)
        # повторная попытка submit уже pending_approval
        result = _submit(wf)
        assert "error" in result

    def test_not_found_returns_error(self, wf):
        result = wf.submit_for_approval("UNKNOWN", 99)
        assert "error" in result

    def test_approved_version_cannot_be_resubmitted(self, wf):
        _make_draft(wf)
        _submit(wf)
        wf.approve("CC6.1", 1, "manager@acme.com")
        result = _submit(wf)
        assert "error" in result


# ══════════════════════════════════════════════════════════════════════════════
# TestApprove
# ══════════════════════════════════════════════════════════════════════════════

class TestApprove:
    def test_pending_to_approved(self, wf):
        _make_draft(wf)
        _submit(wf)
        result = wf.approve("CC6.1", 1, "manager@acme.com")
        assert result["status"] == "approved"

    def test_non_pending_returns_error(self, wf):
        _make_draft(wf)
        result = wf.approve("CC6.1", 1, "manager@acme.com")
        assert "error" in result

    def test_sets_approved_by(self, wf):
        _make_draft(wf)
        _submit(wf)
        wf.approve("CC6.1", 1, "manager@acme.com")
        history = wf.get_history("CC6.1")
        assert history[0]["approved_by"] == "manager@acme.com"

    def test_sets_approved_at(self, wf):
        _make_draft(wf)
        _submit(wf)
        wf.approve("CC6.1", 1, "manager@acme.com")
        history = wf.get_history("CC6.1")
        assert history[0]["approved_at"] is not None

    def test_approve_unknown_version_returns_error(self, wf):
        result = wf.approve("CC6.1", 99, "manager@acme.com")
        assert "error" in result


# ══════════════════════════════════════════════════════════════════════════════
# TestReject
# ══════════════════════════════════════════════════════════════════════════════

class TestReject:
    def test_pending_to_rejected(self, wf):
        _make_draft(wf)
        _submit(wf)
        result = wf.reject("CC6.1", 1, "reviewer@acme.com", "Недостаточно деталей")
        assert result["status"] == "rejected"

    def test_non_pending_returns_error(self, wf):
        _make_draft(wf)
        result = wf.reject("CC6.1", 1, "reviewer@acme.com", "причина")
        assert "error" in result

    def test_has_rejection_reason_field(self, wf):
        _make_draft(wf)
        _submit(wf)
        wf.reject("CC6.1", 1, "reviewer@acme.com", "нужна доработка")
        history = wf.get_history("CC6.1")
        assert history[0]["rejection_reason"] == "нужна доработка"

    def test_has_rejected_by_field(self, wf):
        _make_draft(wf)
        _submit(wf)
        wf.reject("CC6.1", 1, "reviewer@acme.com", "нужна доработка")
        history = wf.get_history("CC6.1")
        assert history[0]["rejected_by"] == "reviewer@acme.com"

    def test_reject_unknown_version_returns_error(self, wf):
        result = wf.reject("CC6.1", 99, "reviewer@acme.com", "причина")
        assert "error" in result


# ══════════════════════════════════════════════════════════════════════════════
# TestGetPending
# ══════════════════════════════════════════════════════════════════════════════

class TestGetPending:
    def test_empty_initially(self, wf):
        assert wf.get_pending() == []

    def test_contains_submitted_version(self, wf):
        _make_draft(wf)
        _submit(wf)
        pending = wf.get_pending()
        assert len(pending) == 1
        assert pending[0]["status"] == "pending_approval"

    def test_approved_not_included_in_pending(self, wf):
        _make_draft(wf)
        _submit(wf)
        wf.approve("CC6.1", 1, "manager@acme.com")
        pending = wf.get_pending()
        assert len(pending) == 0

    def test_rejected_not_included_in_pending(self, wf):
        _make_draft(wf)
        _submit(wf)
        wf.reject("CC6.1", 1, "reviewer@acme.com", "причина")
        pending = wf.get_pending()
        assert len(pending) == 0

    def test_multiple_controls_pending(self, wf):
        _make_draft(wf, code="CC6.1")
        _make_draft(wf, code="CC6.2")
        _submit(wf, code="CC6.1", version=1)
        _submit(wf, code="CC6.2", version=1)
        pending = wf.get_pending()
        assert len(pending) == 2


# ══════════════════════════════════════════════════════════════════════════════
# TestGetHistory
# ══════════════════════════════════════════════════════════════════════════════

class TestGetHistory:
    def test_empty_for_unknown_control(self, wf):
        assert wf.get_history("UNKNOWN") == []

    def test_sorted_descending_by_version(self, wf):
        _make_draft(wf)
        _make_draft(wf)
        _make_draft(wf)
        history = wf.get_history("CC6.1")
        versions = [h["version"] for h in history]
        assert versions == sorted(versions, reverse=True)

    def test_history_count_matches_drafts(self, wf):
        for _ in range(3):
            _make_draft(wf)
        history = wf.get_history("CC6.1")
        assert len(history) == 3

    def test_history_contains_status(self, wf):
        _make_draft(wf)
        history = wf.get_history("CC6.1")
        assert "status" in history[0]
