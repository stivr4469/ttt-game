"""Тесты для DocuSignClient — инициализация, create_envelope, статус, signing URL."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import base64
import json
import pytest
from unittest.mock import patch, MagicMock, call
from docusign_client import DocuSignClient


# ---------------------------------------------------------------------------
# Вспомогательные фабрики
# ---------------------------------------------------------------------------

def make_mock_response(data: dict) -> MagicMock:
    resp = MagicMock()
    resp.content = json.dumps(data).encode()
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


def make_client(account_id="acc-1", token="tok-abc", base_url="https://demo.docusign.net/restapi"):
    return DocuSignClient(account_id=account_id, access_token=token, base_url=base_url)


# ---------------------------------------------------------------------------
# Класс 1: инициализация клиента
# ---------------------------------------------------------------------------

class TestDocuSignClientInit:
    def test_authorization_header_set_with_bearer_token(self):
        client = make_client(token="my-token")
        assert client._session.headers.get("Authorization") == "Bearer my-token"

    def test_content_type_header_set_to_json(self):
        client = make_client()
        assert client._session.headers.get("Content-Type") == "application/json"

    def test_account_id_stored(self):
        client = make_client(account_id="account-xyz")
        assert client.account_id == "account-xyz"

    def test_base_url_stored_without_trailing_slash(self):
        client = make_client(base_url="https://demo.docusign.net/restapi/")
        assert client.base_url == "https://demo.docusign.net/restapi"

    def test_base_url_stored_without_change(self):
        client = make_client(base_url="https://demo.docusign.net/restapi")
        assert client.base_url == "https://demo.docusign.net/restapi"


# ---------------------------------------------------------------------------
# Класс 2: _api — построение URL
# ---------------------------------------------------------------------------

class TestApiUrlBuilding:
    def test_url_includes_account_id(self):
        client = make_client(account_id="my-account")
        mock_resp = make_mock_response({"envelopeId": "env-1", "status": "sent", "uri": "/envelopes/env-1"})
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client._api("GET", "/envelopes/env-1")
        called_url = mock_req.call_args[0][1]
        assert "my-account" in called_url
        assert "/envelopes/env-1" in called_url

    def test_url_includes_v21_version(self):
        client = make_client()
        mock_resp = make_mock_response({})
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client._api("GET", "/envelopes")
        called_url = mock_req.call_args[0][1]
        assert "v2.1" in called_url


# ---------------------------------------------------------------------------
# Класс 3: create_envelope
# ---------------------------------------------------------------------------

class TestCreateEnvelope:
    @pytest.fixture
    def client(self):
        return make_client(account_id="acc-001")

    def test_document_content_encoded_in_base64(self, client):
        api_resp = {"envelopeId": "env-1", "status": "sent", "uri": "/envelopes/env-1"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client.create_envelope("doc.txt", "Hello World", "signer@test.com", "Test User")
        sent_json = mock_req.call_args[1]["json"]
        doc = sent_json["documents"][0]
        decoded = base64.b64decode(doc["documentBase64"]).decode()
        assert decoded == "Hello World"

    def test_body_contains_email_subject(self, client):
        api_resp = {"envelopeId": "env-2", "status": "sent", "uri": "/envelopes/env-2"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client.create_envelope("doc.txt", "content", "s@t.com", "Name", email_subject="Sign this!")
        sent_json = mock_req.call_args[1]["json"]
        assert sent_json["emailSubject"] == "Sign this!"

    def test_body_contains_documents_list(self, client):
        api_resp = {"envelopeId": "env-3", "status": "sent", "uri": "/envelopes/env-3"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client.create_envelope("policy.txt", "text", "s@t.com", "N")
        sent_json = mock_req.call_args[1]["json"]
        assert "documents" in sent_json
        assert len(sent_json["documents"]) == 1
        assert sent_json["documents"][0]["name"] == "policy.txt"

    def test_body_contains_recipients_signers(self, client):
        api_resp = {"envelopeId": "env-4", "status": "sent", "uri": "/envelopes/env-4"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client.create_envelope("doc.txt", "text", "alice@co.com", "Alice")
        sent_json = mock_req.call_args[1]["json"]
        signers = sent_json["recipients"]["signers"]
        assert len(signers) == 1
        assert signers[0]["email"] == "alice@co.com"
        assert signers[0]["name"] == "Alice"

    def test_body_contains_sign_here_tabs(self, client):
        api_resp = {"envelopeId": "env-5", "status": "sent", "uri": "/envelopes/env-5"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client.create_envelope("doc.txt", "text", "s@t.com", "Name")
        sent_json = mock_req.call_args[1]["json"]
        tabs = sent_json["recipients"]["signers"][0]["tabs"]
        assert "signHereTabs" in tabs
        assert len(tabs["signHereTabs"]) >= 1

    def test_status_sent_in_body(self, client):
        api_resp = {"envelopeId": "env-6", "status": "sent", "uri": "/envelopes/env-6"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client.create_envelope("doc.txt", "text", "s@t.com", "Name")
        sent_json = mock_req.call_args[1]["json"]
        assert sent_json["status"] == "sent"

    def test_returns_envelope_id_from_response(self, client):
        api_resp = {"envelopeId": "env-special-123", "status": "sent", "uri": "/envelopes/env-special-123"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp):
            result = client.create_envelope("doc.txt", "text", "s@t.com", "Name")
        assert result["envelope_id"] == "env-special-123"

    def test_returns_status_and_uri(self, client):
        api_resp = {"envelopeId": "env-7", "status": "sent", "uri": "/envelopes/env-7"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp):
            result = client.create_envelope("doc.txt", "text", "s@t.com", "Name")
        assert result["status"] == "sent"
        assert result["uri"] == "/envelopes/env-7"


# ---------------------------------------------------------------------------
# Класс 4: get_envelope_status
# ---------------------------------------------------------------------------

class TestGetEnvelopeStatus:
    @pytest.fixture
    def client(self):
        return make_client()

    def test_makes_get_request_to_envelopes_endpoint(self, client):
        api_resp = {"status": "completed", "completedDateTime": "2026-05-01T12:00:00Z"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client.get_envelope_status("env-abc")
        called_url = mock_req.call_args[0][1]
        assert "/envelopes/env-abc" in called_url
        assert mock_req.call_args[0][0] == "GET"

    def test_returns_envelope_id(self, client):
        api_resp = {"status": "sent", "completedDateTime": None}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp):
            result = client.get_envelope_status("env-xyz")
        assert result["envelope_id"] == "env-xyz"

    def test_returns_status_from_response(self, client):
        api_resp = {"status": "voided", "completedDateTime": None}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp):
            result = client.get_envelope_status("env-xyz")
        assert result["status"] == "voided"

    def test_returns_completed_at_from_response(self, client):
        api_resp = {"status": "completed", "completedDateTime": "2026-05-22T10:00:00Z"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp):
            result = client.get_envelope_status("env-xyz")
        assert result["completed_at"] == "2026-05-22T10:00:00Z"


# ---------------------------------------------------------------------------
# Класс 5: get_signing_url
# ---------------------------------------------------------------------------

class TestGetSigningUrl:
    @pytest.fixture
    def client(self):
        return make_client()

    def test_posts_to_views_recipient_endpoint(self, client):
        api_resp = {"url": "https://app.docusign.com/sign/abc"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp) as mock_req:
            client.get_signing_url("env-1", "s@t.com", "Signer", "https://return.url/")
        called_url = mock_req.call_args[0][1]
        assert "/envelopes/env-1/views/recipient" in called_url
        assert mock_req.call_args[0][0] == "POST"

    def test_returns_url_from_response(self, client):
        api_resp = {"url": "https://app.docusign.com/sign/session-token"}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp):
            url = client.get_signing_url("env-1", "s@t.com", "Signer", "https://return.url/")
        assert url == "https://app.docusign.com/sign/session-token"

    def test_returns_empty_string_when_url_missing(self, client):
        api_resp = {}
        mock_resp = make_mock_response(api_resp)
        with patch.object(client._session, "request", return_value=mock_resp):
            url = client.get_signing_url("env-1", "s@t.com", "Signer", "https://return.url/")
        assert url == ""
