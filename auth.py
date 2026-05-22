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
if len(SECRET_KEY) < 32:
    raise ValueError("JWT_SECRET_KEY must be at least 32 characters")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLES = {
    "admin":   {"can_write": True,  "can_delete": True,  "can_run_scans": True,  "can_view": True},
    "scanner": {"can_write": True,  "can_delete": False, "can_run_scans": True,  "can_view": True},
    "auditor": {"can_write": False, "can_delete": False, "can_run_scans": False, "can_view": True},
    "viewer":  {"can_write": False, "can_delete": False, "can_run_scans": False, "can_view": True},
}

# Хардкод-пользователи для sandbox (в prod — из БД)
USERS_DB = {
    "admin@acme.com":   {"password_hash": pwd_context.hash("admin123"),   "role": "admin",   "name": "Admin User"},
    "auditor@acme.com": {"password_hash": pwd_context.hash("audit123"),   "role": "auditor", "name": "External Auditor"},
    "scanner@acme.com": {"password_hash": pwd_context.hash("scan123"),    "role": "scanner", "name": "Scanner Bot"},
    "viewer@acme.com":  {"password_hash": pwd_context.hash("view123"),    "role": "viewer",  "name": "Report Viewer"},
}

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def authenticate_user(email: str, password: str) -> Optional[dict]:
    user = USERS_DB.get(email)
    if not user or not verify_password(password, user["password_hash"]):
        return None
    return {"email": email, "role": user["role"], "name": user["name"]}

def create_access_token(data: dict) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({**data, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
