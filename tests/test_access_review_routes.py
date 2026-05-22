"""
Тесты для access_review_routes.py.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi import FastAPI
from fastapi.testclient import TestClient
from access_review_routes import router, _USERS


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ══════════════════════════════════════════════════════════════════════════════
# TestGetUsers
# ══════════════════════════════════════════════════════════════════════════════

class TestGetUsers:
    def test_returns_200(self, client):
        resp = client.get("/api/access-review/users")
        assert resp.status_code == 200

    def test_has_review_period(self, client):
        resp = client.get("/api/access-review/users")
        assert "review_period" in resp.json()

    def test_has_users_array(self, client):
        resp = client.get("/api/access-review/users")
        data = resp.json()
        assert "users" in data
        assert isinstance(data["users"], list)

    def test_count_equals_len_users(self, client):
        resp = client.get("/api/access-review/users")
        data = resp.json()
        assert len(data["users"]) == len(_USERS)

    def test_has_generated_at(self, client):
        resp = client.get("/api/access-review/users")
        assert "generated_at" in resp.json()

    def test_users_have_id_field(self, client):
        resp = client.get("/api/access-review/users")
        users = resp.json()["users"]
        assert all("id" in u for u in users)

    def test_all_users_initially_pending(self, client):
        resp = client.get("/api/access-review/users")
        users = resp.json()["users"]
        assert all(u["status"] == "pending" for u in users)


# ══════════════════════════════════════════════════════════════════════════════
# TestPostDecision
# ══════════════════════════════════════════════════════════════════════════════

class TestPostDecision:
    def test_approve_works(self, client):
        resp = client.post("/api/access-review/decision", json={
            "user_id": "u001",
            "decision": "approve",
            "reviewer": "auditor@acme.com",
            "reason": "Доступ подтверждён",
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "approve"

    def test_revoke_works(self, client):
        resp = client.post("/api/access-review/decision", json={
            "user_id": "u002",
            "decision": "revoke",
            "reviewer": "auditor@acme.com",
            "reason": "Сотрудник уволен",
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "revoke"

    def test_invalid_decision_returns_400(self, client):
        resp = client.post("/api/access-review/decision", json={
            "user_id": "u001",
            "decision": "delete",
            "reviewer": "auditor@acme.com",
            "reason": "",
        })
        assert resp.status_code == 400

    def test_unknown_user_id_returns_404(self, client):
        resp = client.post("/api/access-review/decision", json={
            "user_id": "UNKNOWN",
            "decision": "approve",
            "reviewer": "auditor@acme.com",
            "reason": "",
        })
        assert resp.status_code == 404

    def test_decision_reflected_in_users(self, client):
        client.post("/api/access-review/decision", json={
            "user_id": "u003",
            "decision": "revoke",
            "reviewer": "auditor@acme.com",
            "reason": "причина",
        })
        resp = client.get("/api/access-review/users")
        users = {u["id"]: u for u in resp.json()["users"]}
        assert users["u003"]["status"] == "revoke"

    def test_escalate_works(self, client):
        resp = client.post("/api/access-review/decision", json={
            "user_id": "u004",
            "decision": "escalate",
            "reviewer": "auditor@acme.com",
            "reason": "требует ручной проверки",
        })
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# TestSubmitReview
# ══════════════════════════════════════════════════════════════════════════════

class TestSubmitReview:
    def test_returns_status_submitted(self, client):
        resp = client.post("/api/access-review/submit")
        assert resp.status_code == 200
        assert resp.json()["status"] == "submitted"

    def test_has_evidence_ids(self, client):
        resp = client.post("/api/access-review/submit")
        assert "evidence_ids" in resp.json()

    def test_has_summary_with_correct_fields(self, client):
        resp = client.post("/api/access-review/submit")
        summary = resp.json()["summary"]
        for field in ("total", "approved", "revoked", "escalated", "pending"):
            assert field in summary, f"Поле '{field}' отсутствует в summary"

    def test_summary_total_equals_users_count(self, client):
        resp = client.post("/api/access-review/submit")
        summary = resp.json()["summary"]
        assert summary["total"] == len(_USERS)

    def test_summary_pending_decreases_after_decisions(self, client):
        client.post("/api/access-review/decision", json={
            "user_id": "u001", "decision": "approve",
            "reviewer": "aud@acme.com", "reason": "",
        })
        resp = client.post("/api/access-review/submit")
        summary = resp.json()["summary"]
        assert summary["pending"] == len(_USERS) - 1


# ══════════════════════════════════════════════════════════════════════════════
# TestGetStatus
# ══════════════════════════════════════════════════════════════════════════════

class TestGetStatus:
    def test_returns_total_equal_users_count(self, client):
        resp = client.get("/api/access-review/status")
        assert resp.status_code == 200
        assert resp.json()["total"] == len(_USERS)

    def test_pending_initially_equals_total(self, client):
        resp = client.get("/api/access-review/status")
        data = resp.json()
        assert data["pending"] == data["total"]

    def test_reviewed_is_zero_initially(self, client):
        resp = client.get("/api/access-review/status")
        assert resp.json()["reviewed"] == 0

    def test_reviewed_increases_after_decision(self, client):
        client.post("/api/access-review/decision", json={
            "user_id": "u001", "decision": "approve",
            "reviewer": "aud@acme.com", "reason": "",
        })
        resp = client.get("/api/access-review/status")
        assert resp.json()["reviewed"] == 1
