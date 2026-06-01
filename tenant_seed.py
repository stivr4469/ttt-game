"""Создать default tenant в БД (запустить один раз при первом деплое)."""
import asyncio

from sqlalchemy import select

from database import AsyncSessionLocal
from models import Tenant, TenantUser

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"


async def seed_default_tenant() -> None:
    async with AsyncSessionLocal() as session:
        existing = await session.execute(
            select(Tenant).where(Tenant.id == DEFAULT_TENANT_ID)
        )
        if existing.scalar_one_or_none() is None:
            tenant = Tenant(
                id=DEFAULT_TENANT_ID,
                slug="default",
                name="Default Organization",
                status="active",
            )
            session.add(tenant)
            await session.commit()
            print(f"Created default tenant: {DEFAULT_TENANT_ID}")
        else:
            print("Default tenant already exists")

        # Сидировать существующих пользователей из USERS_DB в TenantUser
        from auth import USERS_DB

        for email, user_data in USERS_DB.items():
            existing_user = await session.execute(
                select(TenantUser).where(
                    TenantUser.tenant_id == DEFAULT_TENANT_ID,
                    TenantUser.email == email,
                )
            )
            if existing_user.scalar_one_or_none() is None:
                hashed = user_data.get("password_hash", "")
                session.add(TenantUser(
                    tenant_id=DEFAULT_TENANT_ID,
                    email=email,
                    password_hash=hashed,
                    role=user_data.get("role", "viewer"),
                    name=user_data.get("name", email.split("@")[0]),
                    is_active=True,
                ))
        await session.commit()
        print("Seeded default tenant users")


if __name__ == "__main__":
    asyncio.run(seed_default_tenant())
