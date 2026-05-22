"""Тесты для EvidenceClient — retry логика, API-ключ, обрезка контента."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import requests
from unittest.mock import MagicMock, patch, call
from evidence_client import EvidenceClient, EvidenceClientError, _MAX_RETRIES, _DEFAULT_TIMEOUT


BASE_URL = "http://localhost:8000"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("EVIDENCE_API_KEY", "test-key-123")
    return EvidenceClient(BASE_URL)


@pytest.fixture
def mock_session(client):
    """Патчим session.request и возвращаем mock."""
    with patch.object(client._session, "request") as mock_req:
        yield mock_req


def _ok_response(data: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = data
    resp.raise_for_status.return_value = None
    return resp


def _error_response(status_code: int, text: str = "error") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    http_error = requests.exceptions.HTTPError(response=resp)
    resp.raise_for_status.side_effect = http_error
    return resp


class TestInit:
    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("EVIDENCE_API_KEY", "my-secret-key")
        c = EvidenceClient(BASE_URL)
        assert c._session.headers["X-API-Key"] == "my-secret-key"

    def test_default_api_key(self, monkeypatch):
        monkeypatch.delenv("EVIDENCE_API_KEY", raising=False)
        c = EvidenceClient(BASE_URL)
        assert c._session.headers["X-API-Key"] == "soc2-dev-key"

    def test_trailing_slash_stripped(self):
        c = EvidenceClient("http://localhost:8000/")
        assert c.base_url == "http://localhost:8000"

    def test_default_timeout(self):
        c = EvidenceClient(BASE_URL)
        assert c.timeout == _DEFAULT_TIMEOUT

    def test_custom_timeout(self):
        c = EvidenceClient(BASE_URL, timeout=30)
        assert c.timeout == 30


class TestRetryLogic:
    def test_success_on_first_attempt(self, client, mock_session):
        mock_session.return_value = _ok_response({"id": "1"})
        result = client._request("GET", "/api/v1/controls/")
        assert result == {"id": "1"}
        assert mock_session.call_count == 1

    def test_retries_on_timeout(self, client, mock_session):
        mock_session.side_effect = [
            requests.exceptions.Timeout(),
            requests.exceptions.Timeout(),
            _ok_response({"id": "2"}),
        ]
        result = client._request("GET", "/api/v1/controls/")
        assert result == {"id": "2"}
        assert mock_session.call_count == 3

    def test_retries_on_connection_error(self, client, mock_session):
        mock_session.side_effect = [
            requests.exceptions.ConnectionError(),
            _ok_response({"ok": True}),
        ]
        with patch("time.sleep"):  # не ждём в тестах
            result = client._request("GET", "/api/v1/controls/")
        assert result == {"ok": True}

    def test_raises_after_max_retries(self, client, mock_session):
        mock_session.side_effect = requests.exceptions.Timeout()
        with patch("time.sleep"), pytest.raises(EvidenceClientError, match="retries failed"):
            client._request("GET", "/api/v1/controls/")
        assert mock_session.call_count == _MAX_RETRIES

    def test_no_retry_on_4xx(self, client, mock_session):
        mock_session.return_value = _error_response(422, "Unprocessable Entity")
        with pytest.raises(EvidenceClientError, match="HTTP 422"):
            client._request("POST", "/api/v1/evidence/", json={})
        assert mock_session.call_count == 1  # ровно одна попытка

    def test_retries_on_5xx(self, client, mock_session):
        mock_session.side_effect = [
            _error_response(503, "Service Unavailable"),
            _error_response(503, "Service Unavailable"),
            _error_response(503, "Service Unavailable"),
        ]
        with patch("time.sleep"), pytest.raises(EvidenceClientError, match="retries failed"):
            client._request("GET", "/api/v1/controls/")
        assert mock_session.call_count == _MAX_RETRIES

    def test_correct_url_constructed(self, client, mock_session):
        mock_session.return_value = _ok_response([])
        client._request("GET", "/api/v1/evidence/")
        call_args = mock_session.call_args
        assert call_args[0][1] == "http://localhost:8000/api/v1/evidence/"


class TestCreateEvidence:
    def test_content_truncated_at_limit(self, client, mock_session):
        mock_session.return_value = _ok_response({"id": "x"})
        long_content = "A" * 200_000
        client.create_evidence("ctrl-1", "title", long_content, "AWS_CLI")
        sent_json = mock_session.call_args[1]["json"]
        assert len(sent_json["content"]) <= 99_001 + len("…[truncated]")
        assert sent_json["content"].endswith("…[truncated]")

    def test_short_content_not_truncated(self, client, mock_session):
        mock_session.return_value = _ok_response({"id": "x"})
        content = "small content"
        client.create_evidence("ctrl-1", "title", content, "AWS_CLI")
        sent_json = mock_session.call_args[1]["json"]
        assert sent_json["content"] == "small content"

    def test_title_truncated_at_490(self, client, mock_session):
        mock_session.return_value = _ok_response({"id": "x"})
        long_title = "T" * 600
        client.create_evidence("ctrl-1", long_title, "content", "MANUAL")
        sent_json = mock_session.call_args[1]["json"]
        assert len(sent_json["title"]) == 490

    def test_correct_fields_sent(self, client, mock_session):
        mock_session.return_value = _ok_response({"id": "y"})
        client.create_evidence("ctrl-42", "My Evidence", "content here", "OKTA")
        sent_json = mock_session.call_args[1]["json"]
        assert sent_json["control_id"] == "ctrl-42"
        assert sent_json["title"] == "My Evidence"
        assert sent_json["source"] == "OKTA"


class TestControlMethods:
    def test_update_control_status(self, client, mock_session):
        mock_session.return_value = _ok_response({"status": "PASS"})
        result = client.update_control_status("ctrl-1", "PASS")
        assert result == {"status": "PASS"}
        call_args = mock_session.call_args
        assert "PATCH" in call_args[0]
        assert "/api/v1/controls/ctrl-1/status" in call_args[0][1]

    def test_get_controls_no_filter(self, client, mock_session):
        mock_session.return_value = _ok_response([])
        client.get_controls()
        call_args = mock_session.call_args
        assert call_args[1].get("params") == {}

    def test_get_controls_with_framework_id(self, client, mock_session):
        mock_session.return_value = _ok_response([])
        client.get_controls(framework_id="fw-1")
        call_args = mock_session.call_args
        assert call_args[1]["params"] == {"framework_id": "fw-1"}
