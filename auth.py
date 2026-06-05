import os
import warnings
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import jwt, JWTError
from passlib.context import CryptContext

_DEV_SECRET = "dev-secret-change-in-prod-32chars!!"
SECRET_KEY = os.getenv("JWT_SECRET_KEY", _DEV_SECRET)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 часов

if SECRET_KEY == _DEV_SECRET:
    warnings.warn(
        "JWT_SECRET_KEY is set to the dev default — set JWT_SECRET_KEY env var in production",
        stacklevel=1,
    )
    # Fix: raise in production if the secret is still the dev default
    if os.getenv("ENVIRONMENT") == "production":
        raise RuntimeError("JWT_SECRET_KEY must be set in production")
if len(SECRET_KEY) < 32:
    raise ValueError("JWT_SECRET_KEY must be at least 32 characters")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLES = {
    "admin":   {"can_write": True,  "can_delete": True,  "can_run_scans": True,  "can_view": True},
    "scanner": {"can_write": True,  "can_delete": False, "can_run_scans": True,  "can_view": True},
    "auditor": {"can_write": False, "can_delete": False, "can_run_scans": False, "can_view": True},
    "viewer":  {"can_write": False, "can_delete": False, "can_run_scans": False, "can_view": True},
}

# Pre-computed bcrypt hashes used as non-production fallbacks.
# In production, all four *_PASSWORD_HASH env vars MUST be set.
_FALLBACK_ADMIN_HASH   = "$2b$12$HPqlvz.0CaLygb1pZ9DdUehsXkVWot42lyncsmXprNX0jpWl0tVIC"
_FALLBACK_AUDITOR_HASH = "$2b$12$bRRzpad2QYJzp6sinH7M3u/HKl1CY3dNmqNq/URGA0stGf6Ja12O."
_FALLBACK_SCANNER_HASH = "$2b$12$SDQVig5mfSB7QArhBwbkL.3X9Rn8v0mKtQAfqgPUrqdVHan0Pawh6"
_FALLBACK_VIEWER_HASH  = "$2b$12$58YIOmyaeEHznLv8cl3vXuMVHRYC0ABzUIM.4Ey/ntH5KoLdT1aQ2"

_is_prod = os.getenv("ENVIRONMENT") == "production"

def _load_password_hash(env_var: str, fallback: str) -> str:
    """Load password hash from env var; fall back to pre-computed hash in non-prod only."""
    value = os.getenv(env_var)
    if value:
        return value
    if _is_prod:
        raise RuntimeError(f"{env_var} must be set in production")
    return fallback

# Хардкод-пользователи для sandbox (в prod — из БД)
# NOTE: login endpoint in ui_server.py returns the JWT token in the response body JSON.
#       For production, consider setting it as an HttpOnly cookie instead.
USERS_DB = {
    "admin@acme.com":   {"password_hash": _load_password_hash("ADMIN_PASSWORD_HASH",   _FALLBACK_ADMIN_HASH),   "role": "admin",   "name": "Admin User"},
    "auditor@acme.com": {"password_hash": _load_password_hash("AUDITOR_PASSWORD_HASH", _FALLBACK_AUDITOR_HASH), "role": "auditor", "name": "External Auditor"},
    "scanner@acme.com": {"password_hash": _load_password_hash("SCANNER_PASSWORD_HASH", _FALLBACK_SCANNER_HASH), "role": "scanner", "name": "Scanner Bot"},
    "viewer@acme.com":  {"password_hash": _load_password_hash("VIEWER_PASSWORD_HASH",  _FALLBACK_VIEWER_HASH),  "role": "viewer",  "name": "Report Viewer"},
}

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def authenticate_user(email: str, password: str) -> Optional[dict]:
    user = USERS_DB.get(email)
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return {"email": email, "role": user["role"], "name": user["name"]}

async def get_tenant_user(email: str, password: str, tenant_id: str) -> Optional[dict]:
    """Аутентификация через TenantUser в БД (для Фазы 2 — полная замена USERS_DB)."""
    from database import AsyncSessionLocal
    from models import TenantUser
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(TenantUser).where(
                TenantUser.email == email,
                TenantUser.tenant_id == tenant_id,
                TenantUser.is_active.is_(True),
            )
        )
        user = result.scalar_one_or_none()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return {"email": user.email, "role": user.role, "name": user.name, "tenant_id": user.tenant_id}


def create_access_token(data: dict, tenant_id: str = "00000000-0000-0000-0000-000000000001") -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {**data, "exp": expire}
    if "tenant_id" not in payload:
        payload["tenant_id"] = tenant_id
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


# FastAPI Depends-хелперы для использования в роутерах
try:
    from fastapi import Depends, HTTPException, Cookie, Request

    def require_auth(access_token: Optional[str] = Cookie(default=None)) -> dict:
        """Любой авторизованный пользователь."""
        if not access_token:
            raise HTTPException(status_code=401, detail="Not authenticated")
        payload = decode_token(access_token)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        return payload

    def require_agent_or_auth(
        request: Request,
        access_token: Optional[str] = Cookie(default=None),
    ) -> dict:
        """Cookie-сессия ИЛИ X-API-Key (для агентов-субпроцессов)."""
        import os
        api_key = request.headers.get("X-API-Key", "")
        evidence_key = os.getenv("UI_API_KEY") or os.getenv("EVIDENCE_API_KEY", "")
        if api_key and evidence_key and api_key == evidence_key:
            return {"sub": "agent", "role": "scanner", "name": "agent"}
        return require_auth(access_token)

    def require_admin(user: dict = Depends(require_auth)) -> dict:
        """Только роль admin."""
        if user.get("role") not in ("admin", "Admin"):
            raise HTTPException(status_code=403, detail="Admin role required")
        return user

    def require_auditor(user: dict = Depends(require_auth)) -> dict:
        """Роли admin или auditor."""
        if user.get("role") not in ("admin", "Admin", "auditor", "Auditor"):
            raise HTTPException(status_code=403, detail="Admin or Auditor role required")
        return user

except ImportError:
    # FastAPI не установлен — модуль используется без веб-контекста
    pass
