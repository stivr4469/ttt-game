"""
Тесты для auditor_routes.py.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from auditor_routes import router, VALID_SEVERITIES


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with patch("auditor_routes._evidence_client") as mock_ec:
        mock_ec.get_controls.return_value = []
        mock_ec.get_evidence.return_value = []
        app = FastAPI()
        app.include_router(router)
        yield TestClient(app)


# ══════════════════════════════════════════════════════════════════════════════
# TestValidSeverities
# ══════════════════════════════════════════════════════════════════════════════

class TestValidSeverities:
    def test_observation_in_valid_severities(self):
        assert "observation" in VALID_SEVERITIES

    def test_finding_in_valid_severities(self):
        assert "finding" in VALID_SEVERITIES

    def test_exception_in_valid_severities(self):
        assert "exception" in VALID_SEVERITIES

    def test_invalid_severity_not_in_set(self):
        assert "critical" not in VALID_SEVERITIES


# ══════════════════════════════════════════════════════════════════════════════
# TestAddComment
# ══════════════════════════════════════════════════════════════════════════════

class TestAddComment:
    def _post_comment(self, client, severity="observation", code="CC6.1"):
        return client.post("/api/auditor/comments", json={
            "control_code": code,
            "comment": "Тестовый комментарий",
            "severity": severity,
            "auditor_name": "auditor@acme.com",
        })

    def test_valid_comment_returns_200(self, client):
        resp = self._post_comment(client)
        assert resp.status_code == 200

    def test_response_has_id_field(self, client):
        resp = self._post_comment(client)
        assert "id" in resp.json()

    def test_response_has_control_code(self, client):
        resp = self._post_comment(client, code="CC7.1")
        assert resp.json()["control_code"] == "CC7.1"

    def test_response_has_severity(self, client):
        resp = self._post_comment(client, severity="finding")
        assert resp.json()["severity"] == "finding"

    def test_invalid_severity_returns_400(self, client):
        resp = self._post_comment(client, severity="critical")
        assert resp.status_code == 400

    def test_exception_severity_accepted(self, client):
        resp = self._post_comment(client, severity="exception")
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# TestGetComments
# ══════════════════════════════════════════════════════════════════════════════

class TestGetComments:
    def test_get_comments_returns_list(self, client):
        resp = client.get("/api/auditor/comments")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_initially_empty(self, client):
        resp = client.get("/api/auditor/comments")
        assert resp.json() == []

    def test_filter_by_control_code_works(self, client):
        # Добавим комментарии для двух контролей
        client.post("/api/auditor/comments", json={
            "control_code": "CC6.1",
            "comment": "для CC6.1",
            "severity": "observation",
            "auditor_name": "a@acme.com",
        })
        client.post("/api/auditor/comments", json={
            "control_code": "CC6.2",
            "comment": "для CC6.2",
            "severity": "finding",
            "auditor_name": "a@acme.com",
        })
        resp = client.get("/api/auditor/comments?control_code=CC6.1")
        comments = resp.json()
        assert len(comments) == 1
        assert comments[0]["control_code"] == "CC6.1"

    def test_comment_persisted_after_post(self, client):
        client.post("/api/auditor/comments", json={
            "control_code": "CC6.1",
            "comment": "проверка",
            "severity": "observation",
            "auditor_name": "aud@acme.com",
        })
        resp = client.get("/api/auditor/comments")
        assert len(resp.json()) == 1


# ══════════════════════════════════════════════════════════════════════════════
# TestGetSummary
# ══════════════════════════════════════════════════════════════════════════════

class TestGetSummary:
    def test_returns_total_comments(self, client):
        resp = client.get("/api/auditor/summary")
        assert resp.status_code == 200
        assert "total_comments" in resp.json()

    def test_returns_findings_count(self, client):
        resp = client.get("/api/auditor/summary")
        assert "findings_count" in resp.json()

    def test_returns_exceptions_count(self, client):
        resp = client.get("/api/auditor/summary")
        assert "exceptions_count" in resp.json()

    def test_returns_controls_reviewed(self, client):
        resp = client.get("/api/auditor/summary")
        assert "controls_reviewed" in resp.json()

    def test_counts_are_correct_after_adding_comments(self, client):
        for sev, code in [("finding", "CC6.1"), ("exception", "CC6.2"), ("observation", "CC6.1")]:
            client.post("/api/auditor/comments", json={
                "control_code": code,
                "comment": "text",
                "severity": sev,
                "auditor_name": "a@acme.com",
            })
        resp = client.get("/api/auditor/summary")
        data = resp.json()
        assert data["total_comments"] == 3
        assert data["findings_count"] == 1
        assert data["exceptions_count"] == 1
        # CC6.1 и CC6.2 — два уникальных контроля
        assert data["controls_reviewed"] == 2
