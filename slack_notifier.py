import os
import requests
from typing import Dict, List, Any

from log_config import get_logger

log = get_logger(__name__)

EVIDENCE_TRACKER_URL = os.getenv("EVIDENCE_TRACKER_URL", "http://localhost:8000")


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.severity_icons = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "UNKNOWN": "⚪",
        }

    def send(self, payload: Dict[str, Any]) -> bool:
        """Отправляет JSON payload на Slack webhook."""
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
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
