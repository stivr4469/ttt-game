"""
Tenant Admin API — управление тенантами и их пользователями.

GET    /api/v1/admin/tenants                   — список тенантов
POST   /api/v1/admin/tenants                   — создать тенант
GET    /api/v1/admin/tenants/{tenant_id}        — получить тенант
POST   /api/v1/admin/tenants/{tenant_id}/users  — добавить пользователя в тенант
GET    /api/v1/admin/tenants/{tenant_id}/users  — список пользователей тенанта

Доступ: только роль admin (require_admin из auth).
"""
import uuid
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import require_admin
from database import get_db
from models import Tenant, TenantUser
from secret_store import delete_secret, get_secret, set_oauth_token, set_secret

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/admin/tenants", tags=["admin-tenants"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class TenantCreate(BaseModel):
    slug: str
    name: str
    status: str = "active"


class TenantSecretSet(BaseModel):
    value: str = Field(..., min_length=1)


class OAuthTokenSeed(BaseModel):
    access_token: str = Field(..., min_length=1)
    refresh_token: str = ""
    expires_in: int = Field(..., gt=0, description="Seconds until the access token expires")


class TenantUserCreate(BaseModel):
    email: str
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    role: str = "viewer"
    name: str = ""


# ── Serializers ───────────────────────────────────────────────────────────────

def _serialize_tenant(t: Tenant) -> dict:
    return {
        "id": t.id,
        "slug": t.slug,
        "name": t.name,
        "status": t.status,
        "created_at": t.created_at.isoformat(),
    }


def _serialize_user(u: TenantUser) -> dict:
    return {
        "id": u.id,
        "tenant_id": u.tenant_id,
        "email": u.email,
        "role": u.role,
        "name": u.name,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat(),
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
async def list_tenants(
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Список всех тенантов."""
    result = await session.execute(
        select(Tenant).order_by(Tenant.created_at.asc())
    )
    tenants = result.scalars().all()
    return [_serialize_tenant(t) for t in tenants]


@router.post("", status_code=201)
async def create_tenant(
    body: TenantCreate,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Создать новый тенант. Slug должен быть уникальным."""
    # Проверка уникальности slug
    existing = await session.execute(
        select(Tenant).where(Tenant.slug == body.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Tenant with slug '{body.slug}' already exists")

    tenant = Tenant(
        id=str(uuid.uuid4()),
        slug=body.slug,
        name=body.name,
        status=body.status,
    )
    session.add(tenant)
    await session.commit()
    await session.refresh(tenant)
    return _serialize_tenant(tenant)


@router.get("/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Получить тенант по ID."""
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _serialize_tenant(tenant)


@router.post("/{tenant_id}/users", status_code=201)
async def add_tenant_user(
    tenant_id: str,
    body: TenantUserCreate,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Добавить пользователя в тенант. Email уникален в рамках тенанта."""
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Проверка уникальности email в рамках тенанта
    existing = await session.execute(
        select(TenantUser).where(
            TenantUser.tenant_id == tenant_id,
            TenantUser.email == body.email,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"User '{body.email}' already exists in this tenant",
        )

    from auth import pwd_context
    user = TenantUser(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        email=body.email,
        password_hash=pwd_context.hash(body.password),
        role=body.role,
        name=body.name,
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return _serialize_user(user)


@router.get("/{tenant_id}/users")
async def list_tenant_users(
    tenant_id: str,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Список пользователей тенанта."""
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    result = await session.execute(
        select(TenantUser)
        .where(TenantUser.tenant_id == tenant_id)
        .order_by(TenantUser.created_at.asc())
    )
    users = result.scalars().all()
    return [_serialize_user(u) for u in users]


# ── Tenant Secrets (Fernet-encrypted) ────────────────────────────────────────

@router.put("/{tenant_id}/secrets/{key}", status_code=204)
async def upsert_tenant_secret(
    tenant_id: str,
    key: str,
    body: TenantSecretSet,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    """Store or overwrite an encrypted secret for a tenant."""
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    await set_secret(session, tenant_id, key, body.value)
    await session.commit()


@router.get("/{tenant_id}/secrets/{key}")
async def fetch_tenant_secret(
    tenant_id: str,
    key: str,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> dict:
    """Retrieve a decrypted secret value for a tenant."""
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    value = await get_secret(session, tenant_id, key)
    if value is None:
        raise HTTPException(status_code=404, detail=f"Secret '{key}' not found")
    return {"tenant_id": tenant_id, "key": key, "value": value}


@router.post("/{tenant_id}/secrets/{provider}/oauth-token", status_code=204)
async def seed_oauth_token(
    tenant_id: str,
    provider: str,
    body: OAuthTokenSeed,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    """Seed initial OAuth tokens into the vault for a provider.

    Stores up to three vault keys for the provider:
      {PROVIDER}_ACCESS_TOKEN, {PROVIDER}_TOKEN_EXPIRY, {PROVIDER}_REFRESH_TOKEN
    """
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    await set_oauth_token(
        session,
        tenant_id,
        provider,
        body.access_token,
        body.expires_in,
        body.refresh_token,
    )
    await session.commit()


@router.delete("/{tenant_id}/secrets/{key}", status_code=204)
async def remove_tenant_secret(
    tenant_id: str,
    key: str,
    _: dict = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
) -> None:
    """Delete a tenant secret. Returns 404 if not found."""
    tenant = await session.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    deleted = await delete_secret(session, tenant_id, key)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Secret '{key}' not found")
    await session.commit()
