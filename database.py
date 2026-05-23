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
from typing import AsyncGenerator

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

    return create_async_engine(
        url,
        echo=os.getenv("DB_ECHO", "false").lower() == "true",
        connect_args=connect_args,
        # pool_pre_ping для PostgreSQL: автоматически проверяет соединения
        pool_pre_ping=not is_sqlite,
    )


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

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency для инъекции async DB-сессии.
    Гарантирует закрытие сессии после запроса.

    Использование в роутере:
        from fastapi import Depends
        from database import get_db

        @router.get("/items")
        async def list_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ── Инициализация схемы БД ────────────────────────────────────────────────────

async def init_db() -> None:
    """
    Создаёт все таблицы если их нет (CREATE TABLE IF NOT EXISTS).
    Вызывать при старте приложения один раз.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ── Флаг: доступна ли БД ─────────────────────────────────────────────────────

def is_db_enabled() -> bool:
    """
    Возвращает True если DATABASE_URL задан явно через переменную окружения.
    False → fallback на JSON-файлы (backward compat).

    Dev: по умолчанию DATABASE_URL не задан → is_db_enabled() == False.
    Чтобы включить DB в dev: DATABASE_URL=sqlite+aiosqlite:///./compliance.db
    """
    return bool(os.getenv("DATABASE_URL", ""))
