import os
import time
from typing import Dict, List, Any

import requests

from base_http_client import BaseHTTPClient, _RETRY_BACKOFF
from log_config import get_logger

log = get_logger(__name__)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")


class SlackNotifier(BaseHTTPClient):
    """
    Отправляет сообщения в Slack через Incoming Webhook.
    Наследует retry/backoff от BaseHTTPClient.

    Slack webhook возвращает plain-text "ok", а не JSON, поэтому
    метод _post перегружен: не пытаемся парсить тело ответа.
    """

    def __init__(self, webhook_url: str):
        # base_url = webhook_url; path будет пустым при вызове _post
        super().__init__(base_url=webhook_url, timeout=10)
        self.webhook_url = webhook_url
        self.severity_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "UNKNOWN": "⚪",
        }

    def _post(self, path: str, **kwargs):
        """
        Переопределение: выполняет POST и возвращает объект Response.
        Slack отвечает plain-text ("ok"), не JSON — базовый _post
        пытался бы вызвать resp.json() и упал бы.
        """
        return self._request("POST", f"{self.base_url}{path}", **kwargs)

    def _request(self, method: str, url: str, **kwargs):
        """
        Переопределение базового _request: возвращает объект Response,
        а не resp.json() — Slack отвечает plain-text «ok», не JSON.
        Сохраняет retry/backoff логику для сетевых ошибок.
        """
        kwargs.setdefault("timeout", self.timeout)
        last_exc: Exception = RuntimeError("no attempts made")
        for attempt in range(self.max_retries):
            try:
                resp = self._session.request(method, url, **kwargs)
                # Не вызываем raise_for_status — статус проверяется в send()
                return resp
            except requests.exceptions.RequestException as exc:
                last_exc = exc

            if attempt < self.max_retries - 1:
                wait = _RETRY_BACKOFF ** attempt
                log.warning(
                    "Slack webhook request failed, retrying",
                    extra={"url": url, "attempt": attempt + 1, "wait": wait, "error": str(last_exc)},
                )
                time.sleep(wait)

        log.error(
            "Slack webhook request failed after retries",
            extra={"url": url, "attempts": self.max_retries, "error": str(last_exc)},
        )
        raise last_exc

    def send(self, payload: Dict[str, Any]) -> bool:
        """Отправляет JSON payload на Slack webhook."""
        try:
            response = self._post("", json=payload)
            if response.status_code == 200:
                return True
            log.error(
                "Slack webhook error",
                extra={"status": response.status_code, "body": response.text[:200]},
            )
            return False
        except Exception as e:
            log.error("Failed to send Slack notification", extra={"error": str(e)})
            return False

    def send_scan_summary(self, summary: Dict[str, Any], violations: List[Dict[str, Any]]) -> bool:
        """Форматирует и отправляет итоговое сообщение о результатах скана."""
        high_severity = [v for v in violations if v.get("severity") in ("CRITICAL", "HIGH")]
        high_severity.sort(key=lambda x: 0 if x.get("severity") == "CRITICAL" else 1)

        display = high_severity[:10]
        lines = []
        for v in display:
            icon = self.severity_icons.get(v.get("severity"), "⚪")
            code = v.get("control_code", "UNKNOWN")
            finding = v.get("finding", v.get("title", "No details"))
            source = v.get("source", "UNKNOWN")
            severity = v.get("severity", "UNKNOWN")
            lines.append(f"{icon} [{code}] {finding}  `{source}` `{severity}`")

        if not lines:
            violation_text = "_No Critical or High violations found._"
        else:
            violation_text = "\n".join(lines)
            if len(high_severity) > 10:
                violation_text += f"\n_...and {len(high_severity) - 10} more violations_"

        report_url = f"{EVIDENCE_TRACKER_URL}/docs"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "SOC 2 Compliance Scan Complete"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"✅ *PASS:* {summary.get('pass', 0)}"},
                    {"type": "mrkdwn", "text": f"❌ *FAIL:* {summary.get('fail', 0)}"},
                    {"type": "mrkdwn", "text": f"⏳ *PENDING:* {summary.get('pending', 0)}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Critical & High Violations:*\n{violation_text}"},
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"📋 Full report: {report_url}"},
            },
        ]

        return self.send({"blocks": blocks})

    def send_violation(self, violation: Dict[str, Any]) -> bool:
        """Отправляет одно нарушение отдельным сообщением."""
        icon = self.severity_icons.get(violation.get("severity"), "⚪")
        text = (
            f"{icon} *New Violation Detected*\n"
            f"*Control:* {violation.get('control_code')}\n"
            f"*Severity:* {violation.get('severity')}\n"
            f"*Source:* {violation.get('source')}\n"
            f"*Finding:* {violation.get('finding')}"
        )
        return self.send({
            "text": text,
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
        })

    def send_access_review_request(self, user_info: Dict[str, Any], action_id: str) -> bool:
        """
        Отправляет Block Kit сообщение с кнопками для ревью доступа.
        Кнопки: Подтвердить / Отозвать / Эскалировать.
        """
        username = user_info.get("username", user_info.get("name", "Unknown"))
        email = user_info.get("email", "")
        role = user_info.get("role", user_info.get("department", "N/A"))
        last_login = user_info.get("last_login", "N/A")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🔐 Access Review Required"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*User:* {username}"},
                    {"type": "mrkdwn", "text": f"*Email:* {email}"},
                    {"type": "mrkdwn", "text": f"*Role:* {role}"},
                    {"type": "mrkdwn", "text": f"*Last Login:* {last_login}"},
                ],
            },
            {"type": "divider"},
            {
                "type": "actions",
                "block_id": "access_review_actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Подтвердить доступ"},
                        "style": "primary",
                        "action_id": "confirm_access",
                        "value": action_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🚫 Отозвать доступ"},
                        "style": "danger",
                        "action_id": "revoke_access",
                        "value": action_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "⬆️ Эскалировать"},
                        "action_id": "escalate",
                        "value": action_id,
                    },
                ],
            },
        ]
        return self.send({
            "text": f"Access review required for {username}",
            "blocks": blocks,
        })

    def send_remediation_approval(self, violation: Dict[str, Any], action_id: str) -> bool:
        """
        Отправляет сообщение о нарушении безопасности с кнопками одобрения.
        Кнопки: Авто-исправить / Только уведомить / Отклонить.
        """
        icon = self.severity_icons.get(violation.get("severity"), "⚪")
        control = violation.get("control_code", "UNKNOWN")
        severity = violation.get("severity", "UNKNOWN")
        finding = violation.get("finding", "No details")
        source = violation.get("source", "UNKNOWN")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🛡️ Security Violation — Approval Required"},
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{icon} *{severity}* violation detected\n"
                        f"*Control:* `{control}` | *Source:* `{source}`\n"
                        f"*Finding:* {finding}"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "actions",
                "block_id": "remediation_actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔧 Авто-исправить"},
                        "style": "primary",
                        "action_id": "auto_remediate",
                        "value": action_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "👁️ Только уведомить"},
                        "action_id": "notify_only",
                        "value": action_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Отклонить"},
                        "style": "danger",
                        "action_id": "dismiss",
                        "value": action_id,
                    },
                ],
            },
        ]
        return self.send({
            "text": f"{icon} Security violation {control} requires approval",
            "blocks": blocks,
        })

    def send_incident_alert(self, incident: Dict[str, Any], action_id: str) -> bool:
        """
        Отправляет инцидентный алерт с кнопками реагирования.
        Кнопки: Исправить сейчас / Создать тикет в Jira / Отложить на 24ч.
        """
        title = incident.get("title", incident.get("name", "Security Incident"))
        description = incident.get("description", incident.get("finding", "No details"))
        severity = incident.get("severity", "HIGH")
        icon = self.severity_icons.get(severity, "🔴")
        resource = incident.get("resource", incident.get("bucket", "N/A"))
        incident_type = incident.get("type", incident.get("control_code", "UNKNOWN"))

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Security Incident Detected"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident:* {title}"},
                    {"type": "mrkdwn", "text": f"*Severity:* {icon} {severity}"},
                    {"type": "mrkdwn", "text": f"*Resource:* `{resource}`"},
                    {"type": "mrkdwn", "text": f"*Type:* `{incident_type}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Details:* {description}"},
            },
            {"type": "divider"},
            {
                "type": "actions",
                "block_id": "incident_actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🛠️ Исправить сейчас"},
                        "style": "primary",
                        "action_id": "fix_now",
                        "value": action_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📋 Создать тикет в Jira"},
                        "action_id": "create_jira_ticket",
                        "value": action_id,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "⏰ Отложить на 24ч"},
                        "style": "danger",
                        "action_id": "snooze_24h",
                        "value": action_id,
                    },
                ],
            },
        ]
        return self.send({
            "text": f"🚨 Security incident: {title} ({severity})",
            "blocks": blocks,
        })
