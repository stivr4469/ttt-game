"""Tests for auth.py — JWT lifecycle and FastAPI role enforcement."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from datetime import datetime, timedelta, timezone
from jose import jwt
from passlib.context import CryptContext
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

import auth
from auth import (
    verify_password,
    authenticate_user,
    create_access_token,
    decode_token,
    require_auth,
    require_admin,
    require_auditor,
    SECRET_KEY,
    ALGORITHM,
)

# Low-cost bcrypt for test speed; still verifiable by auth.py's pwd_context
_TEST_CTX = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=4)
_TEST_HASH = _TEST_CTX.hash("testpassword")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _client_for(depend_fn, path="/protected"):
    app = FastAPI()

    @app.get(path)
    def endpoint(user: dict = Depends(depend_fn)):
        return {"role": user.get("role")}

    return TestClient(app, raise_server_exceptions=False)


def _cookie(role: str) -> dict:
    token = create_access_token({"sub": f"{role}@test.com", "role": role})
    return {"access_token": token}


# ── verify_password ────────────────────────────────────────────────────────────

class TestVerifyPassword:
    def test_correct_password(self):
        assert verify_password("testpassword", _TEST_HASH) is True

    def test_wrong_password(self):
        assert verify_password("wrong", _TEST_HASH) is False

    def test_empty_password(self):
        assert verify_password("", _TEST_HASH) is False


# ── create_access_token / decode_token ────────────────────────────────────────

class TestJwt:
    def test_roundtrip_preserves_claims(self):
        token = create_access_token({"sub": "u@t.com", "role": "viewer"})
        payload = decode_token(token)
        assert payload["sub"] == "u@t.com"
        assert payload["role"] == "viewer"

    def test_token_includes_exp(self):
        token = create_access_token({"sub": "u", "role": "admin"})
        payload = decode_token(token)
        assert "exp" in payload

    def test_token_includes_tenant_id(self):
        token = create_access_token({"sub": "u", "role": "admin"})
        payload = decode_token(token)
        assert "tenant_id" in payload

    def test_custom_tenant_id_stored(self):
        token = create_access_token({"sub": "u", "role": "admin"}, tenant_id="my-tenant")
        payload = decode_token(token)
        assert payload["tenant_id"] == "my-tenant"

    def test_existing_tenant_id_in_data_not_overwritten(self):
        token = create_access_token({"sub": "u", "role": "admin", "tenant_id": "from-data"})
        payload = decode_token(token)
        assert payload["tenant_id"] == "from-data"

    def test_decode_returns_none_for_garbage(self):
        assert decode_token("not.a.token") is None

    def test_decode_returns_none_for_tampered_signature(self):
        token = create_access_token({"sub": "u", "role": "admin"})
        tampered = token[:-4] + "XXXX"
        assert decode_token(tampered) is None

    def test_decode_returns_none_for_expired_token(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        expired = jwt.encode({"sub": "u", "exp": past}, SECRET_KEY, algorithm=ALGORITHM)
        assert decode_token(expired) is None

    def test_decode_returns_none_for_wrong_key(self):
        token = jwt.encode({"sub": "u", "role": "admin"}, "wrong-key-32-chars-minimum!!!!", algorithm=ALGORITHM)
        assert decode_token(token) is None


# ── authenticate_user ──────────────────────────────────────────────────────────

class TestAuthenticateUser:
    def test_unknown_email_returns_none(self):
        assert authenticate_user("ghost@example.com", "any") is None

    def test_known_email_wrong_password_returns_none(self, monkeypatch):
        monkeypatch.setitem(auth.USERS_DB, "test@test.com", {
            "password_hash": _TEST_HASH, "role": "viewer", "name": "Test",
        })
        assert authenticate_user("test@test.com", "wrongpassword") is None

    def test_valid_credentials_return_user_dict(self, monkeypatch):
        monkeypatch.setitem(auth.USERS_DB, "test@test.com", {
            "password_hash": _TEST_HASH, "role": "viewer", "name": "Test User",
        })
        result = authenticate_user("test@test.com", "testpassword")
        assert result is not None
        assert result["email"] == "test@test.com"
        assert result["role"] == "viewer"
        assert result["name"] == "Test User"

    def test_result_does_not_include_password_hash(self, monkeypatch):
        monkeypatch.setitem(auth.USERS_DB, "test@test.com", {
            "password_hash": _TEST_HASH, "role": "admin", "name": "Admin",
        })
        result = authenticate_user("test@test.com", "testpassword")
        assert "password_hash" not in result


# ── require_auth ───────────────────────────────────────────────────────────────

class TestRequireAuth:
    def test_no_cookie_returns_401(self):
        client = _client_for(require_auth)
        assert client.get("/protected").status_code == 401

    def test_bad_token_returns_401(self):
        client = _client_for(require_auth)
        resp = client.get("/protected", cookies={"access_token": "bad.tok.en"})
        assert resp.status_code == 401

    def test_valid_token_returns_200_with_role(self):
        client = _client_for(require_auth)
        resp = client.get("/protected", cookies=_cookie("viewer"))
        assert resp.status_code == 200
        assert resp.json()["role"] == "viewer"

    def test_expired_token_returns_401(self):
        client = _client_for(require_auth)
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        expired = jwt.encode({"sub": "u", "exp": past}, SECRET_KEY, algorithm=ALGORITHM)
        resp = client.get("/protected", cookies={"access_token": expired})
        assert resp.status_code == 401


# ── require_admin ──────────────────────────────────────────────────────────────

class TestRequireAdmin:
    def setup_method(self):
        self.client = _client_for(require_admin, "/admin")

    def test_viewer_returns_403(self):
        assert self.client.get("/admin", cookies=_cookie("viewer")).status_code == 403

    def test_auditor_returns_403(self):
        assert self.client.get("/admin", cookies=_cookie("auditor")).status_code == 403

    def test_scanner_returns_403(self):
        assert self.client.get("/admin", cookies=_cookie("scanner")).status_code == 403

    def test_admin_returns_200(self):
        assert self.client.get("/admin", cookies=_cookie("admin")).status_code == 200

    def test_no_cookie_returns_401(self):
        assert self.client.get("/admin").status_code == 401


# ── require_auditor ────────────────────────────────────────────────────────────

class TestRequireAuditor:
    def setup_method(self):
        self.client = _client_for(require_auditor, "/audit")

    def test_viewer_returns_403(self):
        assert self.client.get("/audit", cookies=_cookie("viewer")).status_code == 403

    def test_scanner_returns_403(self):
        assert self.client.get("/audit", cookies=_cookie("scanner")).status_code == 403

    def test_auditor_returns_200(self):
        assert self.client.get("/audit", cookies=_cookie("auditor")).status_code == 200

    def test_admin_returns_200(self):
        assert self.client.get("/audit", cookies=_cookie("admin")).status_code == 200

    def test_no_cookie_returns_401(self):
        assert self.client.get("/audit").status_code == 401
