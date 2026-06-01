"""
Async SQLAlchemy engine, Base, и FastAPI dependency get_db.

Dev-режим (по умолчанию): aiosqlite + файл compliance.db в корне проекта.
Prod-режим: asyncpg через переменную окружения DATABASE_URL.

Примеры DATABASE_URL:
  sqlite+aiosqlite:///./compliance.db          — SQLite (dev, default)
  postgresql+asyncpg://user:pass@host/dbname   — PostgreSQL (prod)
"""

from __future__ import annotations

import os
from typing import AsyncGenerator, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# ── Базовый класс для всех ORM-моделей ───────────────────────────────────────

class Base(DeclarativeBase):
    """Базовый класс SQLAlchemy ORM."""
    pass


# ── Получение DATABASE_URL из окружения ──────────────────────────────────────

def _get_database_url() -> str:
    """
    Возвращает DATABASE_URL из переменной окружения.
    Если не задан — возвращает SQLite/aiosqlite для dev-режима.
    """
    url = os.getenv("DATABASE_URL", "")
    if not url:
        # Dev: SQLite файл в корне проекта
        db_path = os.path.join(os.path.dirname(__file__), "compliance.db")
        return f"sqlite+aiosqlite:///{db_path}"
    # Поддержка старого формата "postgresql://..." → "postgresql+asyncpg://..."
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


# ── Создание движка и фабрики сессий ─────────────────────────────────────────

def _create_engine(url: str) -> AsyncEngine:
    """Создаёт async engine с настройками под тип БД."""
    is_sqlite = url.startswith("sqlite")
    connect_args: dict = {}
    if is_sqlite:
        # SQLite требует check_same_thread=False для async
        connect_args["check_same_thread"] = False

    common_kwargs: dict = {
        "echo": os.getenv("DB_ECHO", "false").lower() == "true",
        "connect_args": connect_args,
        "pool_pre_ping": True,
    }

    if not is_sqlite:
        # SQLite не поддерживает pool_size/max_overflow (использует StaticPool)
        common_kwargs["pool_size"] = int(os.getenv("DB_POOL_SIZE", "20"))
        common_kwargs["max_overflow"] = int(os.getenv("DB_MAX_OVERFLOW", "10"))
        common_kwargs["pool_timeout"] = int(os.getenv("DB_POOL_TIMEOUT", "30"))
        common_kwargs["pool_recycle"] = int(os.getenv("DB_POOL_RECYCLE", "1800"))

    return create_async_engine(url, **common_kwargs)


DATABASE_URL: str = _get_database_url()
engine: AsyncEngine = _create_engine(DATABASE_URL)

# Фабрика сессий — expire_on_commit=False важно для async (избегает lazy loading)
AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ── FastAPI dependency ────────────────────────────────────────────────────────

async def get_db(request=None) -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency для инъекции async DB-сессии.
    Гарантирует закрытие сессии после запроса.
    Выставляет tenant_id в session.info для app-level tenant isolation (SQLite RLS).
    Для PostgreSQL дополнительно выполняет SET LOCAL app.tenant_id для RLS на уровне БД.

    Контракт commit/rollback:
        Routes must call ``await session.commit()`` explicitly.
        get_db only rolls back on exception — it never auto-commits.

    Использование в роутере:
        from fastapi import Depends
        from database import get_db

        @router.get("/items")
        async def list_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    from tenant_context import get_current_tenant_id
    async with AsyncSessionLocal() as session:
        tenant_id = get_current_tenant_id()
        if tenant_id:
            # Для всех БД: сохраняем в info сессии (app-level isolation)
            session.info["tenant_id"] = tenant_id
            # Для PostgreSQL: выставляем app.tenant_id через SET LOCAL для row-level security
            if not DATABASE_URL.startswith("sqlite"):
                await session.execute(
                    text("SET LOCAL app.tenant_id = :tid"), {"tid": str(tenant_id)}
                )
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


# ── Инициализация схемы БД ────────────────────────────────────────────────────

async def init_db() -> None:
    """
    Creates all tables for SQLite dev mode (CREATE TABLE IF NOT EXISTS).
    For PostgreSQL, run Alembic migrations instead: `alembic upgrade head`.
    Call once at application startup.
    """
    import models  # noqa: F401 — registers ORM classes in Base.metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# Алиас для совместимости с кодом агентов
get_async_session = get_db


async def check_db_health() -> bool:
    """
    Проверяет доступность БД через простой SELECT 1.
    Возвращает True если соединение успешно, False при любой ошибке.
    """
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_tenant_id_from_session(session: AsyncSession) -> Optional[str]:
    """Получить tenant_id из session.info (выставляется tenant-aware get_db)."""
    return session.info.get("tenant_id")


# ── Флаг: доступна ли БД ─────────────────────────────────────────────────────

def is_db_enabled() -> bool:
    """
    Возвращает True если DATABASE_URL задан явно через переменную окружения.
    False → fallback на JSON-файлы (backward compat).

    Dev: по умолчанию DATABASE_URL не задан → is_db_enabled() == False.
    Чтобы включить DB в dev: DATABASE_URL=sqlite+aiosqlite:///./compliance.db
    """
    return bool(os.getenv("DATABASE_URL", ""))
