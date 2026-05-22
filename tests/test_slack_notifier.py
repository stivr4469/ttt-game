"""Тесты для SlackNotifier — send, send_scan_summary, send_violation."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import requests
from unittest.mock import patch, MagicMock
from slack_notifier import SlackNotifier

WEBHOOK_URL = "https://hooks.slack.com/services/TEST/TEST/TEST"


@pytest.fixture
def notifier():
    return SlackNotifier(WEBHOOK_URL)


def _mock_post(status_code: int = 200, text: str = "ok"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


class TestSend:
    def test_returns_true_on_200(self, notifier):
        with patch("requests.post", return_value=_mock_post(200)) as mock_post:
            result = notifier.send({"text": "hello"})
        assert result is True
        mock_post.assert_called_once_with(WEBHOOK_URL, json={"text": "hello"}, timeout=10)

    def test_returns_false_on_non_200(self, notifier):
        with patch("requests.post", return_value=_mock_post(400, "Bad Request")):
            result = notifier.send({"text": "hello"})
        assert result is False

    def test_returns_false_on_exception(self, notifier):
        with patch("requests.post", side_effect=requests.exceptions.ConnectionError("no route")):
            result = notifier.send({"text": "hello"})
        assert result is False

    def test_returns_false_on_timeout(self, notifier):
        with patch("requests.post", side_effect=requests.exceptions.Timeout()):
            result = notifier.send({"text": "hello"})
        assert result is False

    def test_payload_sent_as_json(self, notifier):
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send({"blocks": [{"type": "section"}]})
        call_kwargs = mock_post.call_args[1]
        assert "json" in call_kwargs
        assert call_kwargs["json"]["blocks"][0]["type"] == "section"


class TestSeverityIcons:
    def test_critical_icon(self, notifier):
        assert notifier.severity_icons["CRITICAL"] == "🔴"

    def test_high_icon(self, notifier):
        assert notifier.severity_icons["HIGH"] == "🟠"

    def test_medium_icon(self, notifier):
        assert notifier.severity_icons["MEDIUM"] == "🟡"

    def test_low_icon(self, notifier):
        assert notifier.severity_icons["LOW"] == "🔵"

    def test_unknown_icon(self, notifier):
        assert notifier.severity_icons["UNKNOWN"] == "⚪"


class TestSendViolation:
    def _make_violation(self, severity="CRITICAL"):
        return {
            "control_code": "CC6.1",
            "severity": severity,
            "source": "AWS_CLI",
            "finding": "SSH port 22 open to 0.0.0.0/0",
        }

    def test_returns_bool(self, notifier):
        with patch("requests.post", return_value=_mock_post()):
            result = notifier.send_violation(self._make_violation())
        assert isinstance(result, bool)

    def test_payload_contains_control_code(self, notifier):
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_violation(self._make_violation())
        payload = mock_post.call_args[1]["json"]
        text = payload["text"]
        assert "CC6.1" in text

    def test_payload_contains_severity(self, notifier):
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_violation(self._make_violation("HIGH"))
        payload = mock_post.call_args[1]["json"]
        assert "HIGH" in payload["text"]

    def test_payload_contains_finding(self, notifier):
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_violation(self._make_violation())
        payload = mock_post.call_args[1]["json"]
        assert "SSH port 22" in payload["text"]

    def test_critical_gets_red_icon(self, notifier):
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_violation(self._make_violation("CRITICAL"))
        payload = mock_post.call_args[1]["json"]
        assert "🔴" in payload["text"]

    def test_unknown_severity_gets_white_icon(self, notifier):
        violation = self._make_violation()
        violation["severity"] = "UNDEFINED"
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_violation(violation)
        payload = mock_post.call_args[1]["json"]
        assert "⚪" in payload["text"]


class TestSendScanSummary:
    def _make_summary(self, pass_=15, fail=18, pending=0):
        return {"pass": pass_, "fail": fail, "pending": pending}

    def _make_violations(self, n: int, severity="CRITICAL"):
        return [
            {"control_code": f"CC6.{i}", "severity": severity,
             "finding": f"Finding {i}", "source": "AWS_CLI"}
            for i in range(n)
        ]

    def test_returns_bool(self, notifier):
        with patch("requests.post", return_value=_mock_post()):
            result = notifier.send_scan_summary(self._make_summary(), [])
        assert isinstance(result, bool)

    def test_no_violations_shows_empty_message(self, notifier):
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_scan_summary(self._make_summary(), [])
        payload = mock_post.call_args[1]["json"]
        payload_str = str(payload)
        assert "No Critical or High violations" in payload_str

    def test_pass_count_in_payload(self, notifier):
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_scan_summary(self._make_summary(pass_=15), [])
        payload_str = str(mock_post.call_args[1]["json"])
        assert "15" in payload_str

    def test_fail_count_in_payload(self, notifier):
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_scan_summary(self._make_summary(fail=18), [])
        payload_str = str(mock_post.call_args[1]["json"])
        assert "18" in payload_str

    def test_max_10_violations_shown(self, notifier):
        violations = self._make_violations(15)
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_scan_summary(self._make_summary(), violations)
        payload_str = str(mock_post.call_args[1]["json"])
        assert "5 more violations" in payload_str

    def test_critical_sorted_before_high(self, notifier):
        violations = [
            {"control_code": "CC6.1", "severity": "HIGH", "finding": "High finding", "source": "AWS_CLI"},
            {"control_code": "CC6.2", "severity": "CRITICAL", "finding": "Critical finding", "source": "AWS_CLI"},
        ]
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_scan_summary(self._make_summary(), violations)
        payload_str = str(mock_post.call_args[1]["json"])
        # CRITICAL должен быть раньше HIGH в строке
        critical_idx = payload_str.index("Critical finding")
        high_idx = payload_str.index("High finding")
        assert critical_idx < high_idx

    def test_low_severity_filtered_out(self, notifier):
        violations = [
            {"control_code": "CC6.1", "severity": "LOW", "finding": "Low finding", "source": "AWS_CLI"},
        ]
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_scan_summary(self._make_summary(), violations)
        payload_str = str(mock_post.call_args[1]["json"])
        assert "Low finding" not in payload_str
        assert "No Critical or High violations" in payload_str

    def test_medium_severity_filtered_out(self, notifier):
        violations = [
            {"control_code": "CC7.1", "severity": "MEDIUM", "finding": "Medium finding", "source": "OKTA"},
        ]
        with patch("requests.post", return_value=_mock_post()) as mock_post:
            notifier.send_scan_summary(self._make_summary(), violations)
        payload_str = str(mock_post.call_args[1]["json"])
        assert "Medium finding" not in payload_str
