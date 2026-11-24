"""
Async SQLAlchemy engine/session setup. Works with SQLite out of the box for
local development and swaps to Postgres in production by changing DATABASE_URL.
"""
import hashlib

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()
engine_options = {"echo": False, "future": True, "pool_pre_ping": True}
if settings.database_url.startswith("postgresql+asyncpg"):
    engine_options.update(
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
        pool_timeout=settings.database_pool_timeout,
    )
engine = create_async_engine(settings.database_url, **engine_options)
AsyncSessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    if settings.environment in {"production", "prod"}:
        return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if settings.database_url.startswith("sqlite+aiosqlite"):
            result = await conn.exec_driver_sql("PRAGMA table_info(api_keys)")
            columns = {row[1] for row in result.fetchall()}
            if "key_hash" not in columns:
                await conn.exec_driver_sql(
                    "ALTER TABLE api_keys ADD COLUMN key_hash VARCHAR"
                )
                await conn.exec_driver_sql(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ix_api_keys_key_hash "
                    "ON api_keys(key_hash)"
                )
            if "key_prefix" not in columns:
                await conn.exec_driver_sql(
                    "ALTER TABLE api_keys ADD COLUMN key_prefix VARCHAR"
                )
            result = await conn.exec_driver_sql(
                "SELECT id, key FROM api_keys WHERE key_hash IS NULL"
            )
            for key_id, raw_key in result.fetchall():
                key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
                await conn.exec_driver_sql(
                    "UPDATE api_keys SET key = ?, key_hash = ?, key_prefix = ? WHERE id = ?",
                    (key_hash, key_hash, raw_key[:12], key_id),
                )
