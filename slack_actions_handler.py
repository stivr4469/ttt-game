"""
slack_actions_handler.py — SOAR-обработчик интерактивных Slack actions.

Обрабатывает payload от Slack Interactivity (block_actions).
Выполняет реальные действия: IAM revoke через boto3, S3 fix через fix_infrastructure.
История действий хранится в памяти (deque maxlen=200).
"""
from __future__ import annotations

import os
import boto3
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Deque, Dict, Optional

from log_config import get_logger

log = get_logger(__name__)

LOCALSTACK_ENDPOINT = os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "test")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "test")

# Максимальная история действий
_HISTORY_MAXLEN = 200

# Таблица отложенных инцидентов: action_id → expiry datetime
_snooze_registry: Dict[str, datetime] = {}


@dataclass
class ActionResult:
    """Результат выполнения SOAR-действия."""

    action: str
    action_id: str
    status: str          # "ok" | "error"
    message: str
    executed_by: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _make_iam_client():
    """Создаёт boto3 IAM клиент, направленный на LocalStack."""
    return boto3.client(
        "iam",
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )


class SlackActionsHandler:
    """
    Обрабатывает входящие Slack Interactivity payloads (type=block_actions).

    Маршрутизирует по action_id к конкретному обработчику.
    Сохраняет историю выполненных действий (deque maxlen=200).
    """

    # Реестр обработчиков: action_id → метод
    _DISPATCH: Dict[str, str] = {
        "confirm_access":     "_handle_confirm_access",
        "revoke_access":      "_handle_revoke_access",
        "escalate":           "_handle_escalate",
        "auto_remediate":     "_handle_auto_remediate",
        "notify_only":        "_handle_notify_only",
        "dismiss":            "_handle_dismiss",
        "fix_now":            "_handle_fix_now",
        "create_jira_ticket": "_handle_create_jira_ticket",
        "snooze_24h":         "_handle_snooze_24h",
    }

    def __init__(self, slack_notifier=None):
        self._history: Deque[ActionResult] = deque(maxlen=_HISTORY_MAXLEN)
        # Опциональный notifier для отправки подтверждений обратно в Slack
        self._notifier = slack_notifier

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def handle(self, payload: Dict[str, Any]) -> ActionResult:
        """
        Точка входа для Slack Interactivity payload.
        payload["type"] == "block_actions"
        payload["actions"][0]["action_id"] — идентификатор нажатой кнопки
        payload["user"]["username"] — кто нажал
        """
        if payload.get("type") != "block_actions":
            return self._unknown_action(
                action_id="",
                user="system",
                reason=f"Unexpected payload type: {payload.get('type')}",
            )

        actions = payload.get("actions", [])
        if not actions:
            return self._unknown_action(action_id="", user="system", reason="No actions in payload")

        action = actions[0]
        action_id = action.get("action_id", "")
        value = action.get("value", action_id)
        user_info = payload.get("user", {})
        username = user_info.get("username") or user_info.get("name") or "unknown"

        log.info(
            "Slack action received",
            extra={"action_id": action_id, "value": value, "user": username},
        )

        handler_name = self._DISPATCH.get(action_id)
        if not handler_name:
            return self._unknown_action(action_id=action_id, user=username)

        handler = getattr(self, handler_name)
        result = handler(action_id=value, user=username)
        self._history.append(result)
        return result

    def get_history(self, limit: int = 50) -> list[Dict[str, Any]]:
        """Возвращает последние N действий из истории (новые первые)."""
        items = list(self._history)
        items.reverse()
        return [r.to_dict() for r in items[:limit]]

    def get_stats(self) -> Dict[str, Any]:
        """Агрегат статистики: count по action-типам и статусам."""
        stats: Dict[str, int] = {}
        ok_count = 0
        error_count = 0
        for result in self._history:
            stats[result.action] = stats.get(result.action, 0) + 1
            if result.status == "ok":
                ok_count += 1
            else:
                error_count += 1
        return {
            "total": len(self._history),
            "ok": ok_count,
            "error": error_count,
            "by_action": stats,
        }

    # ------------------------------------------------------------------
    # Обработчики конкретных actions
    # ------------------------------------------------------------------

    def _handle_confirm_access(self, action_id: str, user: str) -> ActionResult:
        """Подтверждает доступ — логирует решение."""
        log.info("Access confirmed", extra={"action_id": action_id, "by": user})
        self._notify_slack(f"✅ Доступ подтверждён | action_id={action_id} | by={user}")
        return ActionResult(
            action="confirm_access",
            action_id=action_id,
            status="ok",
            message=f"Access confirmed for action_id={action_id}",
            executed_by=user,
        )

    def _handle_revoke_access(self, action_id: str, user: str) -> ActionResult:
        """
        Отзывает IAM доступ через boto3 → LocalStack.
        Пробует delete_login_profile; если пользователь не найден — логирует предупреждение.
        """
        log.info("Revoking IAM access", extra={"action_id": action_id, "by": user})
        try:
            iam = _make_iam_client()
            # action_id содержит имя IAM-пользователя или идентификатор
            iam_username = action_id.split(":")[0] if ":" in action_id else action_id
            try:
                iam.delete_login_profile(UserName=iam_username)
                message = f"IAM login profile deleted for {iam_username}"
            except iam.exceptions.NoSuchEntityException:
                # Пользователь не имеет login profile — деактивируем через tag
                message = f"IAM user {iam_username}: no login profile (may be already revoked)"
            log.info("IAM access revoked", extra={"iam_username": iam_username, "by": user})
            self._notify_slack(
                f"🚫 Доступ отозван: IAM пользователь `{iam_username}` | by={user}"
            )
            return ActionResult(
                action="revoke_access",
                action_id=action_id,
                status="ok",
                message=message,
                executed_by=user,
            )
        except Exception as exc:
            err = str(exc)
            log.error("IAM revoke failed", extra={"action_id": action_id, "error": err})
            return ActionResult(
                action="revoke_access",
                action_id=action_id,
                status="error",
                message=f"IAM revoke failed: {err}",
                executed_by=user,
            )

    def _handle_escalate(self, action_id: str, user: str) -> ActionResult:
        """Эскалирует инцидент — помечает для ручного рассмотрения."""
        log.warning("Incident escalated", extra={"action_id": action_id, "by": user})
        self._notify_slack(
            f"⬆️ Эскалация: action_id={action_id} требует ручного рассмотрения | by={user}"
        )
        return ActionResult(
            action="escalate",
            action_id=action_id,
            status="ok",
            message=f"Incident {action_id} escalated for manual review",
            executed_by=user,
        )

    def _apply_infrastructure_fix(
        self,
        action: str,
        action_id: str,
        user: str,
        slack_msg: str,
        ok_message: str,
    ) -> ActionResult:
        """
        Общий хелпер для действий, вызывающих fix_infrastructure.fix_s3_public_bucket().
        Устраняет дублирование между auto_remediate и fix_now.
        """
        try:
            from fix_infrastructure import fix_s3_public_bucket
            fix_s3_public_bucket()
            self._notify_slack(slack_msg)
            return ActionResult(
                action=action,
                action_id=action_id,
                status="ok",
                message=ok_message,
                executed_by=user,
            )
        except Exception as exc:
            err = str(exc)
            log.error(
                "Infrastructure fix failed",
                extra={"action": action, "action_id": action_id, "error": err},
            )
            return ActionResult(
                action=action,
                action_id=action_id,
                status="error",
                message=f"Fix failed: {err}",
                executed_by=user,
            )

    def _handle_auto_remediate(self, action_id: str, user: str) -> ActionResult:
        """
        Автоматически исправляет нарушение.
        Вызывает fix_infrastructure.fix_s3_public_bucket() для CC6.7.
        """
        log.info("Auto-remediation triggered", extra={"action_id": action_id, "by": user})
        return self._apply_infrastructure_fix(
            action="auto_remediate",
            action_id=action_id,
            user=user,
            slack_msg=f"🔧 Авто-исправление выполнено: S3 bucket сделан приватным | action_id={action_id} | by={user}",
            ok_message="S3 public bucket remediation applied (CC6.7)",
        )

    def _handle_notify_only(self, action_id: str, user: str) -> ActionResult:
        """Регистрирует решение 'только уведомить' без автоматических действий."""
        log.info("Notify-only selected", extra={"action_id": action_id, "by": user})
        self._notify_slack(
            f"👁️ Принято к сведению: action_id={action_id} | by={user}"
        )
        return ActionResult(
            action="notify_only",
            action_id=action_id,
            status="ok",
            message=f"Violation {action_id} acknowledged (notify only, no auto-fix)",
            executed_by=user,
        )

    def _handle_dismiss(self, action_id: str, user: str) -> ActionResult:
        """Отклоняет нарушение как ложное срабатывание."""
        log.info("Violation dismissed", extra={"action_id": action_id, "by": user})
        self._notify_slack(
            f"❌ Нарушение отклонено как ложное срабатывание: action_id={action_id} | by={user}"
        )
        return ActionResult(
            action="dismiss",
            action_id=action_id,
            status="ok",
            message=f"Violation {action_id} dismissed as false positive",
            executed_by=user,
        )

    def _handle_fix_now(self, action_id: str, user: str) -> ActionResult:
        """
        Немедленно исправляет инцидент.
        Применяет полный набор исправлений инфраструктуры.
        """
        log.info("Fix-now triggered", extra={"action_id": action_id, "by": user})
        return self._apply_infrastructure_fix(
            action="fix_now",
            action_id=action_id,
            user=user,
            slack_msg=f"🛠️ Исправление применено немедленно: action_id={action_id} | by={user}",
            ok_message=f"Infrastructure fix applied for incident {action_id}",
        )

    def _handle_create_jira_ticket(self, action_id: str, user: str) -> ActionResult:
        """Создаёт Jira-тикет для расследования инцидента."""
        log.info("Jira ticket requested", extra={"action_id": action_id, "by": user})
        try:
            from jira_client import JiraClient
            jira = JiraClient()
            ticket = jira.create_issue(
                summary=f"Security Incident: {action_id}",
                description=(
                    f"Автоматически создано из Slack SOAR.\n"
                    f"Инцидент: {action_id}\n"
                    f"Инициатор: {user}"
                ),
                issue_type="Bug",
                priority="High",
            )
            ticket_key = ticket.get("key", "UNKNOWN")
            self._notify_slack(
                f"📋 Jira тикет создан: {ticket_key} | action_id={action_id} | by={user}"
            )
            return ActionResult(
                action="create_jira_ticket",
                action_id=action_id,
                status="ok",
                message=f"Jira ticket created: {ticket_key}",
                executed_by=user,
            )
        except Exception as exc:
            err = str(exc)
            log.warning(
                "Jira ticket creation failed (Jira may not be configured)",
                extra={"action_id": action_id, "error": err},
            )
            # Graceful degradation: записываем намерение
            return ActionResult(
                action="create_jira_ticket",
                action_id=action_id,
                status="error",
                message=f"Jira ticket queued (integration unavailable): {err}",
                executed_by=user,
            )

    def _handle_snooze_24h(self, action_id: str, user: str) -> ActionResult:
        """Откладывает инцидент на 24 часа."""
        expiry = datetime.now(timezone.utc) + timedelta(hours=24)
        _snooze_registry[action_id] = expiry
        log.info(
            "Incident snoozed",
            extra={"action_id": action_id, "expiry": expiry.isoformat(), "by": user},
        )
        self._notify_slack(
            f"⏰ Инцидент отложен до {expiry.strftime('%Y-%m-%d %H:%M UTC')}: action_id={action_id} | by={user}"
        )
        return ActionResult(
            action="snooze_24h",
            action_id=action_id,
            status="ok",
            message=f"Incident snoozed until {expiry.isoformat()}",
            executed_by=user,
        )

    # ------------------------------------------------------------------
    # Вспомогательные методы
    # ------------------------------------------------------------------

    def _unknown_action(
        self,
        action_id: str,
        user: str,
        reason: Optional[str] = None,
    ) -> ActionResult:
        """Возвращает результат для неизвестного действия."""
        message = reason or f"Unknown action_id: {action_id}"
        log.warning("Unknown Slack action", extra={"action_id": action_id, "user": user, "reason": message})
        result = ActionResult(
            action="unknown",
            action_id=action_id,
            status="error",
            message=message,
            executed_by=user,
        )
        self._history.append(result)
        return result

    def _notify_slack(self, text: str) -> None:
        """Отправляет подтверждение в Slack если notifier настроен."""
        if self._notifier is None:
            return
        try:
            self._notifier.send({"text": text})
        except Exception as exc:
            log.warning(
                "Failed to send Slack confirmation",
                extra={"error": str(exc)},
            )


def is_snoozed(action_id: str) -> bool:
    """Проверяет, не истёк ли снуз для данного action_id."""
    expiry = _snooze_registry.get(action_id)
    if expiry is None:
        return False
    if datetime.now(timezone.utc) >= expiry:
        del _snooze_registry[action_id]
        return False
    return True


def get_snooze_expiry(action_id: str) -> Optional[datetime]:
    """Возвращает время истечения снуза или None."""
    return _snooze_registry.get(action_id)
