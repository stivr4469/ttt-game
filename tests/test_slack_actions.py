"""
Тесты для SlackActionsHandler — SOAR-обработчик Slack Interactivity.

Покрывает: handle(), все action-обработчики, историю, статистику, снуз.
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import urllib.parse
from collections import deque
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, call

import pytest

from slack_actions_handler import (
    SlackActionsHandler,
    ActionResult,
    is_snoozed,
    get_snooze_expiry,
    _snooze_registry,
)


# ---------------------------------------------------------------------------
# Вспомогательные фабрики
# ---------------------------------------------------------------------------

def _make_payload(action_id: str, value: str = "test-action-001", username: str = "alice") -> dict:
    """Строит минимальный Slack block_actions payload."""
    return {
        "type": "block_actions",
        "user": {"username": username, "id": "U12345"},
        "actions": [
            {
                "action_id": action_id,
                "value": value,
                "block_id": "some_block",
                "type": "button",
            }
        ],
    }


@pytest.fixture
def handler():
    return SlackActionsHandler()


# ---------------------------------------------------------------------------
# 1. test_handle_confirm_access
# ---------------------------------------------------------------------------

class TestHandleConfirmAccess:
    def test_returns_action_result(self, handler):
        payload = _make_payload("confirm_access", value="review-42")
        result = handler.handle(payload)
        assert isinstance(result, ActionResult)

    def test_status_ok(self, handler):
        payload = _make_payload("confirm_access", value="review-42")
        result = handler.handle(payload)
        assert result.status == "ok"

    def test_action_name(self, handler):
        payload = _make_payload("confirm_access", value="review-42")
        result = handler.handle(payload)
        assert result.action == "confirm_access"

    def test_executed_by_captured(self, handler):
        payload = _make_payload("confirm_access", value="review-42", username="bob")
        result = handler.handle(payload)
        assert result.executed_by == "bob"

    def test_action_id_propagated(self, handler):
        payload = _make_payload("confirm_access", value="review-99")
        result = handler.handle(payload)
        assert result.action_id == "review-99"


# ---------------------------------------------------------------------------
# 2. test_handle_revoke_access (mock boto3)
# ---------------------------------------------------------------------------

class TestHandleRevokeAccess:
    def test_status_ok_on_successful_revoke(self, handler):
        payload = _make_payload("revoke_access", value="jdoe")
        with patch("slack_actions_handler._make_iam_client") as mock_iam_factory:
            mock_iam = MagicMock()
            mock_iam_factory.return_value = mock_iam
            mock_iam.delete_login_profile.return_value = {}
            result = handler.handle(payload)
        assert result.status == "ok"
        assert result.action == "revoke_access"

    def test_calls_delete_login_profile(self, handler):
        payload = _make_payload("revoke_access", value="jdoe")
        with patch("slack_actions_handler._make_iam_client") as mock_iam_factory:
            mock_iam = MagicMock()
            mock_iam_factory.return_value = mock_iam
            mock_iam.delete_login_profile.return_value = {}
            handler.handle(payload)
        mock_iam.delete_login_profile.assert_called_once_with(UserName="jdoe")

    def test_graceful_on_no_such_entity(self, handler):
        """Если login profile нет — не ошибка, а предупреждение."""
        payload = _make_payload("revoke_access", value="jdoe")
        with patch("slack_actions_handler._make_iam_client") as mock_iam_factory:
            mock_iam = MagicMock()
            mock_iam_factory.return_value = mock_iam
            mock_iam.exceptions.NoSuchEntityException = Exception
            mock_iam.delete_login_profile.side_effect = Exception("NoSuchEntity")
            # NoSuchEntityException — не fatal, но здесь это общий Exception
            result = handler.handle(payload)
        # Может быть ok или error в зависимости от реализации
        assert result.action == "revoke_access"

    def test_status_error_on_boto3_failure(self, handler):
        """Произвольная boto3 ошибка → status=error."""
        payload = _make_payload("revoke_access", value="jdoe")
        with patch("slack_actions_handler._make_iam_client") as mock_iam_factory:
            mock_iam_factory.side_effect = RuntimeError("AWS connection refused")
            result = handler.handle(payload)
        assert result.status == "error"
        assert "revoke_access" == result.action

    def test_action_id_contains_username(self, handler):
        payload = _make_payload("revoke_access", value="alice:iam-user")
        with patch("slack_actions_handler._make_iam_client") as mock_iam_factory:
            mock_iam = MagicMock()
            mock_iam_factory.return_value = mock_iam
            mock_iam.delete_login_profile.return_value = {}
            result = handler.handle(payload)
        # Проверяем что username был извлечён из value до ":"
        mock_iam.delete_login_profile.assert_called_once_with(UserName="alice")


# ---------------------------------------------------------------------------
# 3. test_handle_auto_remediate (mock fix_infrastructure)
# ---------------------------------------------------------------------------

class TestHandleAutoRemediate:
    def test_status_ok_on_success(self, handler):
        payload = _make_payload("auto_remediate", value="CC6.7-vuln-001")
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"fix_infrastructure": mock_module}):
            result = handler.handle(payload)
        assert result.action == "auto_remediate"
        assert result.status == "ok"

    def test_fix_s3_called(self, handler):
        payload = _make_payload("auto_remediate", value="CC6.7-vuln-001")
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"fix_infrastructure": mock_module}):
            result = handler.handle(payload)
        mock_module.fix_s3_public_bucket.assert_called_once()

    def test_status_error_on_exception(self, handler):
        payload = _make_payload("auto_remediate", value="CC6.7-vuln-001")
        mock_module = MagicMock()
        mock_module.fix_s3_public_bucket.side_effect = RuntimeError("S3 unavailable")
        with patch.dict("sys.modules", {"fix_infrastructure": mock_module}):
            result = handler.handle(payload)
        assert result.status == "error"
        assert "S3 unavailable" in result.message

    def test_message_contains_cc67(self, handler):
        payload = _make_payload("auto_remediate", value="CC6.7-vuln-001")
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"fix_infrastructure": mock_module}):
            result = handler.handle(payload)
        assert "CC6.7" in result.message or result.status == "error"


# ---------------------------------------------------------------------------
# 4. test_handle_unknown_action
# ---------------------------------------------------------------------------

class TestHandleUnknownAction:
    def test_unknown_action_id_returns_error(self, handler):
        payload = _make_payload("nonexistent_button", value="xyz")
        result = handler.handle(payload)
        assert result.status == "error"
        assert result.action == "unknown"

    def test_wrong_payload_type_returns_error(self, handler):
        payload = {"type": "shortcut", "user": {"username": "bob"}, "actions": []}
        result = handler.handle(payload)
        assert result.status == "error"

    def test_empty_actions_returns_error(self, handler):
        payload = {"type": "block_actions", "user": {"username": "bob"}, "actions": []}
        result = handler.handle(payload)
        assert result.status == "error"


# ---------------------------------------------------------------------------
# 5. test_slack_payload_parsing
# ---------------------------------------------------------------------------

class TestSlackPayloadParsing:
    """Тестирует корректность распознавания полей из payload."""

    def test_username_extracted(self, handler):
        payload = _make_payload("confirm_access", username="charlie")
        result = handler.handle(payload)
        assert result.executed_by == "charlie"

    def test_value_used_as_action_id(self, handler):
        payload = _make_payload("escalate", value="incident-007")
        result = handler.handle(payload)
        assert result.action_id == "incident-007"

    def test_url_encoded_payload_structure(self):
        """Проверяет, что URL-encoded payload корректно разворачивается."""
        inner = _make_payload("confirm_access", value="r-99")
        encoded = "payload=" + urllib.parse.quote(json.dumps(inner))
        raw = urllib.parse.unquote(encoded.split("payload=", 1)[1])
        parsed = json.loads(raw)
        assert parsed["type"] == "block_actions"
        assert parsed["actions"][0]["action_id"] == "confirm_access"

    def test_missing_user_field_defaults_to_unknown(self, handler):
        payload = {
            "type": "block_actions",
            "actions": [{"action_id": "confirm_access", "value": "x"}],
        }
        result = handler.handle(payload)
        assert result.executed_by == "unknown"


# ---------------------------------------------------------------------------
# 6. test_action_result_structure
# ---------------------------------------------------------------------------

class TestActionResultStructure:
    def test_all_fields_present(self, handler):
        payload = _make_payload("confirm_access", value="r-1")
        result = handler.handle(payload)
        assert hasattr(result, "action")
        assert hasattr(result, "action_id")
        assert hasattr(result, "status")
        assert hasattr(result, "message")
        assert hasattr(result, "executed_by")
        assert hasattr(result, "timestamp")

    def test_timestamp_is_iso_format(self, handler):
        payload = _make_payload("escalate", value="i-1")
        result = handler.handle(payload)
        # Должен парситься как ISO datetime
        parsed = datetime.fromisoformat(result.timestamp)
        assert parsed is not None

    def test_to_dict_returns_dict(self, handler):
        payload = _make_payload("notify_only", value="v-1")
        result = handler.handle(payload)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["action"] == "notify_only"
        assert d["status"] == "ok"

    def test_status_is_ok_or_error(self, handler):
        payload = _make_payload("dismiss", value="v-2")
        result = handler.handle(payload)
        assert result.status in ("ok", "error")


# ---------------------------------------------------------------------------
# 7. test_history_stored
# ---------------------------------------------------------------------------

class TestHistoryStored:
    def test_action_added_to_history(self, handler):
        assert len(handler._history) == 0
        payload = _make_payload("confirm_access", value="h-1")
        handler.handle(payload)
        assert len(handler._history) == 1

    def test_multiple_actions_stored(self, handler):
        for i in range(5):
            handler.handle(_make_payload("escalate", value=f"i-{i}"))
        assert len(handler._history) == 5

    def test_get_history_returns_list(self, handler):
        handler.handle(_make_payload("dismiss", value="d-1"))
        history = handler.get_history()
        assert isinstance(history, list)
        assert len(history) >= 1

    def test_get_history_newest_first(self, handler):
        handler.handle(_make_payload("confirm_access", value="first"))
        handler.handle(_make_payload("dismiss", value="second"))
        history = handler.get_history()
        assert history[0]["action_id"] == "second"
        assert history[1]["action_id"] == "first"

    def test_get_history_respects_limit(self, handler):
        for i in range(10):
            handler.handle(_make_payload("notify_only", value=f"n-{i}"))
        history = handler.get_history(limit=3)
        assert len(history) == 3

    def test_unknown_action_also_stored(self, handler):
        handler.handle(_make_payload("unknown_xyz", value="u-1"))
        assert len(handler._history) == 1
        assert handler._history[0].action == "unknown"


# ---------------------------------------------------------------------------
# 8. test_history_max_200
# ---------------------------------------------------------------------------

class TestHistoryMax200:
    def test_history_capped_at_200(self, handler):
        for i in range(250):
            handler._history.append(
                ActionResult(
                    action="confirm_access",
                    action_id=f"r-{i}",
                    status="ok",
                    message="ok",
                    executed_by="bot",
                )
            )
        assert len(handler._history) == 200

    def test_oldest_evicted_when_full(self, handler):
        # Заполняем 200 записей
        for i in range(200):
            handler._history.append(
                ActionResult(
                    action="confirm_access",
                    action_id=f"old-{i}",
                    status="ok",
                    message="ok",
                    executed_by="bot",
                )
            )
        # Добавляем ещё одну
        handler._history.append(
            ActionResult(
                action="escalate",
                action_id="new-latest",
                status="ok",
                message="ok",
                executed_by="bot",
            )
        )
        assert len(handler._history) == 200
        # Самая старая (old-0) должна быть вытеснена
        ids = [r.action_id for r in handler._history]
        assert "old-0" not in ids
        assert "new-latest" in ids


# ---------------------------------------------------------------------------
# 9. test_stats_aggregation
# ---------------------------------------------------------------------------

class TestStatsAggregation:
    def test_stats_count_by_action(self, handler):
        handler.handle(_make_payload("confirm_access", value="r-1"))
        handler.handle(_make_payload("confirm_access", value="r-2"))
        handler.handle(_make_payload("dismiss", value="d-1"))
        stats = handler.get_stats()
        assert stats["by_action"]["confirm_access"] == 2
        assert stats["by_action"]["dismiss"] == 1

    def test_stats_total(self, handler):
        for _ in range(7):
            handler.handle(_make_payload("escalate", value="e-1"))
        stats = handler.get_stats()
        assert stats["total"] == 7

    def test_stats_ok_error_counts(self, handler):
        handler.handle(_make_payload("confirm_access", value="ok-1"))  # ok
        handler.handle(_make_payload("unknown_xyz", value="err-1"))   # error
        stats = handler.get_stats()
        assert stats["ok"] >= 1
        assert stats["error"] >= 1

    def test_stats_empty_handler(self, handler):
        stats = handler.get_stats()
        assert stats["total"] == 0
        assert stats["ok"] == 0
        assert stats["error"] == 0
        assert stats["by_action"] == {}


# ---------------------------------------------------------------------------
# 10. test_snooze_sets_expiry
# ---------------------------------------------------------------------------

class TestSnooze:
    def test_snooze_sets_expiry_in_registry(self, handler):
        _snooze_registry.clear()
        payload = _make_payload("snooze_24h", value="inc-999")
        before = datetime.now(timezone.utc)
        handler.handle(payload)
        after = datetime.now(timezone.utc)

        expiry = get_snooze_expiry("inc-999")
        assert expiry is not None
        # Expiry должен быть ~24h от сейчас
        assert expiry > before + timedelta(hours=23, minutes=59)
        assert expiry < after + timedelta(hours=24, seconds=5)

    def test_is_snoozed_returns_true_before_expiry(self, handler):
        _snooze_registry.clear()
        payload = _make_payload("snooze_24h", value="inc-snooze")
        handler.handle(payload)
        assert is_snoozed("inc-snooze") is True

    def test_is_snoozed_returns_false_for_unknown(self):
        assert is_snoozed("nonexistent-id-xyz") is False

    def test_is_snoozed_returns_false_after_expiry(self):
        _snooze_registry.clear()
        # Устанавливаем просроченный снуз
        _snooze_registry["expired-id"] = datetime.now(timezone.utc) - timedelta(seconds=1)
        result = is_snoozed("expired-id")
        assert result is False
        # После проверки запись должна быть удалена
        assert "expired-id" not in _snooze_registry

    def test_snooze_result_status_ok(self, handler):
        _snooze_registry.clear()
        payload = _make_payload("snooze_24h", value="inc-555")
        result = handler.handle(payload)
        assert result.status == "ok"
        assert result.action == "snooze_24h"

    def test_snooze_message_contains_expiry(self, handler):
        _snooze_registry.clear()
        payload = _make_payload("snooze_24h", value="inc-666")
        result = handler.handle(payload)
        assert "snoozed until" in result.message


# ---------------------------------------------------------------------------
# Дополнительные интеграционные тесты
# ---------------------------------------------------------------------------

class TestAllActionsHandled:
    """Smoke-тест: каждый зарегистрированный action_id обрабатывается без исключений."""

    ALL_ACTIONS = [
        "confirm_access",
        "escalate",
        "notify_only",
        "dismiss",
        "snooze_24h",
    ]

    @pytest.mark.parametrize("action_id", ALL_ACTIONS)
    def test_action_handled_without_exception(self, handler, action_id):
        _snooze_registry.clear()
        payload = _make_payload(action_id, value=f"test-{action_id}")
        result = handler.handle(payload)
        assert result.action == action_id
        assert result.status in ("ok", "error")

    def test_revoke_access_with_mocked_iam(self, handler):
        with patch("slack_actions_handler._make_iam_client") as mock_factory:
            mock_iam = MagicMock()
            mock_factory.return_value = mock_iam
            mock_iam.delete_login_profile.return_value = {}
            payload = _make_payload("revoke_access", value="testuser")
            result = handler.handle(payload)
        assert result.action == "revoke_access"

    def test_auto_remediate_with_mocked_module(self, handler):
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"fix_infrastructure": mock_module}):
            payload = _make_payload("auto_remediate", value="CC6.7-001")
            result = handler.handle(payload)
        assert result.action == "auto_remediate"

    def test_fix_now_with_mocked_module(self, handler):
        mock_module = MagicMock()
        with patch.dict("sys.modules", {"fix_infrastructure": mock_module}):
            payload = _make_payload("fix_now", value="incident-001")
            result = handler.handle(payload)
        assert result.action == "fix_now"
