"""
Тесты RemediationAgent и JiraClient (Task 28).
"""
import os
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock


# ── JiraClient ─────────────────────────────────────────────────────────────


class TestJiraClientCreateIssue:
    """JiraClient.create_issue строит корректный ADF payload."""

    def _make_client(self, captured: dict):
        from jira_client import JiraClient

        def mock_request(method, url, **kwargs):
            captured["body"] = kwargs.get("json", {})
            resp = MagicMock()
            resp.content = b'{"key": "SEC-42", "id": "12345"}'
            resp.json.return_value = {"key": "SEC-42", "id": "12345"}
            resp.raise_for_status = MagicMock()
            return resp

        with patch("requests.Session.request", side_effect=mock_request):
            c = JiraClient("https://acme.atlassian.net", "user@acme.com", "token")
            result = c.create_issue("SEC", "Test summary", "Test description", priority="Critical")
        return result, captured

    def test_returns_correct_key(self):
        captured = {}
        result, _ = self._make_client(captured)
        assert result["key"] == "SEC-42"

    def test_priority_field_in_payload(self):
        captured = {}
        _, cap = self._make_client(captured)
        assert cap["body"]["fields"]["priority"]["name"] == "Critical"

    def test_soc2_label_in_payload(self):
        captured = {}
        _, cap = self._make_client(captured)
        assert "soc2" in cap["body"]["fields"]["labels"]

    def test_adf_description_format(self):
        captured = {}
        _, cap = self._make_client(captured)
        desc = cap["body"]["fields"]["description"]
        assert desc["type"] == "doc"
        assert desc["version"] == 1
        assert desc["content"][0]["type"] == "paragraph"

    def test_url_contains_issue_key(self):
        captured = {}
        result, _ = self._make_client(captured)
        assert "SEC-42" in result["url"]


# ── RemediationAgent ────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_remediations(tmp_path, monkeypatch):
    """Перенаправляет REMEDIATIONS_FILE в tmp_path."""
    import remediation_agent
    monkeypatch.setattr(remediation_agent, "REMEDIATIONS_FILE", str(tmp_path / "remediations.json"))
    return tmp_path


class TestRemediationAgentMockMode:
    """Mock-режим — без env-vars создаёт mock тикеты."""

    @pytest.fixture()
    def agent(self, tmp_remediations):
        with patch("remediation_agent.EvidenceClient"):
            from remediation_agent import RemediationAgent
            return RemediationAgent()

    def test_processes_only_fail_controls(self, agent):
        controls = [
            {"control_code": "CC6.1", "status": "FAIL", "finding": "MFA not enforced"},
            {"control_code": "CC7.1", "status": "FAIL", "finding": "CloudTrail disabled"},
            {"control_code": "CC6.6", "status": "PASS", "finding": ""},
        ]
        results = agent.process_fail_controls(controls)
        assert len(results) == 2

    def test_mock_tickets_have_jira_key(self, agent):
        controls = [
            {"control_code": "CC6.1", "status": "FAIL", "finding": "MFA not enforced"},
        ]
        results = agent.process_fail_controls(controls)
        assert "jira_key" in results[0]

    def test_mock_flag_is_true(self, agent):
        controls = [
            {"control_code": "CC6.1", "status": "FAIL", "finding": "MFA not enforced"},
        ]
        results = agent.process_fail_controls(controls)
        assert results[0]["mock"] is True

    def test_idempotent_no_duplicate_tickets(self, agent):
        controls = [
            {"control_code": "CC6.1", "status": "FAIL", "finding": "MFA not enforced"},
        ]
        results1 = agent.process_fail_controls(controls)
        results2 = agent.process_fail_controls(controls)
        assert results2[0]["jira_key"] == results1[0]["jira_key"]

    def test_skips_pass_controls(self, agent):
        controls = [
            {"control_code": "CC6.6", "status": "PASS", "finding": ""},
        ]
        results = agent.process_fail_controls(controls)
        assert results == []


class TestRemediationAgentSyncStatuses:
    """sync_statuses без ключей → пустой список."""

    def test_returns_empty_list_without_keys(self, tmp_remediations):
        with patch("remediation_agent.EvidenceClient"):
            from remediation_agent import RemediationAgent
            agent = RemediationAgent()
        result = agent.sync_statuses()
        assert result == []


class TestRemediationAgentPriorities:
    """Проверка PRIORITY_MAP для известных контролей."""

    @pytest.fixture()
    def agent(self, tmp_remediations):
        with patch("remediation_agent.EvidenceClient"):
            from remediation_agent import RemediationAgent
            return RemediationAgent()

    def test_cc6_1_is_critical(self, agent):
        controls = [{"control_code": "CC6.1", "status": "FAIL", "finding": "test"}]
        results = agent.process_fail_controls(controls)
        assert results[0]["priority"] == "Critical"

    def test_cc7_1_is_high(self, agent):
        controls = [{"control_code": "CC7.1", "status": "FAIL", "finding": "test"}]
        results = agent.process_fail_controls(controls)
        assert results[0]["priority"] == "High"

    def test_unknown_control_is_medium(self, agent):
        controls = [{"control_code": "CC9.9", "status": "FAIL", "finding": "unknown"}]
        results = agent.process_fail_controls(controls)
        assert results[0]["priority"] == "Medium"


class TestRemediationFile:
    """Проверка корректности структуры remediations.json."""

    def test_remediations_json_is_valid(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "remediations.json")
        with open(path) as f:
            data = json.load(f)
        assert "remediations" in data
        assert isinstance(data["remediations"], dict)
