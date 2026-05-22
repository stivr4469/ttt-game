"""
Тесты для agent_name параметра EvidenceClient (Task #14).
Статус: КРАСНЫЕ до завершения Task #14 Джимми, ЗЕЛЁНЫЕ после.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import inspect
from unittest.mock import MagicMock, patch
from evidence_client import EvidenceClient


def _ok_response(data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = data
    resp.raise_for_status.return_value = None
    return resp


class TestAgentNameParameter:
    """Task #14: каждый агент использует собственный API-ключ по имени."""

    def test_init_accepts_agent_name_param(self):
        """EvidenceClient должен принимать agent_name как параметр."""
        sig = inspect.signature(EvidenceClient.__init__)
        assert "agent_name" in sig.parameters, (
            "Task #14 не завершён: EvidenceClient.__init__ не принимает agent_name"
        )

    def test_agent_specific_env_var_used(self, monkeypatch):
        """scanner → читает SCANNER_API_KEY из env."""
        monkeypatch.setenv("SCANNER_API_KEY", "scanner-secret-key")
        monkeypatch.delenv("EVIDENCE_API_KEY", raising=False)
        c = EvidenceClient("http://localhost:8000", agent_name="scanner")
        assert c._session.headers["X-API-Key"] == "scanner-secret-key"

    def test_github_agent_env_var(self, monkeypatch):
        """github_agent → читает GITHUB_AGENT_API_KEY из env."""
        monkeypatch.setenv("GITHUB_AGENT_API_KEY", "github-agent-key")
        c = EvidenceClient("http://localhost:8000", agent_name="github_agent")
        assert c._session.headers["X-API-Key"] == "github-agent-key"

    def test_fallback_to_evidence_api_key(self, monkeypatch):
        """Если {AGENT}_API_KEY не задан — fallback на EVIDENCE_API_KEY."""
        monkeypatch.delenv("SCANNER_API_KEY", raising=False)
        monkeypatch.setenv("EVIDENCE_API_KEY", "fallback-key")
        c = EvidenceClient("http://localhost:8000", agent_name="scanner")
        assert c._session.headers["X-API-Key"] == "fallback-key"

    def test_default_fallback_without_any_env(self, monkeypatch):
        """Без env vars → дефолтный ключ soc2-dev-key."""
        monkeypatch.delenv("SCANNER_API_KEY", raising=False)
        monkeypatch.delenv("EVIDENCE_API_KEY", raising=False)
        c = EvidenceClient("http://localhost:8000", agent_name="scanner")
        assert c._session.headers["X-API-Key"] == "soc2-dev-key"

    def test_default_agent_name_no_break(self, monkeypatch):
        """Без agent_name — старое поведение не сломано."""
        monkeypatch.setenv("EVIDENCE_API_KEY", "legacy-key")
        c = EvidenceClient("http://localhost:8000")
        assert c._session.headers["X-API-Key"] == "legacy-key"

    def test_env_var_name_uppercased(self, monkeypatch):
        """Имя агента приводится к UPPER_CASE для env var."""
        monkeypatch.setenv("UI_API_KEY", "ui-dashboard-key")
        c = EvidenceClient("http://localhost:8000", agent_name="ui")
        assert c._session.headers["X-API-Key"] == "ui-dashboard-key"

    def test_different_agents_use_different_keys(self, monkeypatch):
        """Два агента с разными именами получают разные ключи."""
        monkeypatch.setenv("SCANNER_API_KEY", "key-for-scanner")
        monkeypatch.setenv("HR_AGENT_API_KEY", "key-for-hr")
        scanner_client = EvidenceClient("http://localhost:8000", agent_name="scanner")
        hr_client = EvidenceClient("http://localhost:8000", agent_name="hr_agent")
        assert scanner_client._session.headers["X-API-Key"] == "key-for-scanner"
        assert hr_client._session.headers["X-API-Key"] == "key-for-hr"
        assert scanner_client._session.headers["X-API-Key"] != hr_client._session.headers["X-API-Key"]
